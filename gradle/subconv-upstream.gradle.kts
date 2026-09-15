// ===========================================================================
// 上游同步（pull → 自动套补丁 → 自检）与内核校验
//
// 这是「跟进上游」的**正式入口**，用 Gradle 写是为了跨平台：
// .github/workflows/manual-build.yml 跑在 ubuntu 上，Windows 专用脚本在那儿用不了。
//
//   ./gradlew syncUpstream                              同步到 tools/upstream-ref.txt 的锚点
//   ./gradlew syncUpstream -Psubconv.dryRun=true         只看差多少，一个字都不写
//   ./gradlew syncUpstream -Psubconv.ref=67fba3a -Psubconv.updatePin=true
//   ./gradlew syncUpstream -Psubconv.fetch=true          先 git fetch（本地克隆）或克隆/更新
//   ./gradlew verifyKernel                               核对 APK 里三个 ABI 的 .so
//
// 而且**默认挂在构建上**：:app 的 preBuild / native 任务都先依赖 syncUpstream，所以
//
//   ./gradlew :app:assembleRelease
//
// 一条命令就是 pull → 套补丁 → 编内核 → .so 进 APK 的 lib/<abi>/。不想让它碰上游就加
// -Psubconv.syncOnBuild=false（离线，或者只想编当前工作区）。
//
// 内核仍然由 AGP（externalNativeBuild + CMake）从 app/src/main/cpp 的源码编，
// 这个插件**不产出 .so** —— 它只负责把「上游源码 + Android 适配补丁」这块准备好，
// 打好包时 .so 自然落到 APK 的 lib/<abi>/ 里（可用 verifyKernel 核对）。
//
// 边界清单（UPSTREAM_DIRS / UPSTREAM_FILES / ANDROID_OWNED）只有这一份定义，
// 文档和别人写的清单都是它的镜像 —— 加边界只改这里。
// ===========================================================================
import org.gradle.api.DefaultTask
import org.gradle.api.GradleException
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.provider.ProviderFactory
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.InputDirectory
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.Internal
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations
import java.io.ByteArrayOutputStream
import java.io.File
import java.security.MessageDigest
import java.time.LocalDate
import java.time.LocalDateTime
import java.util.zip.ZipFile
import javax.inject.Inject

// ---------------------------------------------------------------------------
// syncUpstream：拉上游 → 覆盖 vendor 目录 → 套 patches/ → 自检
//
// 刻意**不**自动改 CMakeLists.txt 的源文件列表：上游新增 .cpp 时这里只报警告，
// 由人加一行。自动改构建配置是静默的，写错了要到链接期才炸。
// ---------------------------------------------------------------------------
abstract class SyncUpstreamTask @Inject constructor(
    private val execOps: ExecOperations,
) : DefaultTask() {

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val pinFile: ConfigurableFileCollection

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val patchFiles: ConfigurableFileCollection

    @get:InputDirectory
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val cppDir: DirectoryProperty

    @get:Input
    abstract val ref: Property<String>

    @get:Input
    abstract val upstream: Property<String>

    @get:Input
    abstract val gitExe: Property<String>

    @get:Input
    abstract val dryRun: Property<Boolean>

    @get:Input
    abstract val doFetch: Property<Boolean>

    @get:Input
    abstract val reject: Property<Boolean>

    @get:Input
    abstract val updatePin: Property<Boolean>

    /** 严格模式：CMakeLists 的源文件列表和上游对不上时直接失败（CI 上开，见 workflow）。 */
    @get:Input
    abstract val strict: Property<Boolean>

    @get:Internal
    abstract val siblingUpstream: DirectoryProperty

    @get:Internal
    abstract val workDir: DirectoryProperty

    @get:Internal
    abstract val cloneCache: DirectoryProperty

    private companion object {
        // 上游所属：会被上游内容原样覆盖（含删除）
        val UPSTREAM_DIRS = listOf(
            "include/subconv",
            "src/core", "src/codec", "src/parse", "src/fetch", "src/emit", "src/server",
            "third_party/nlohmann",
        )
        val UPSTREAM_FILES = listOf("data/web/index.html")

        // Android 自己的：本任务一概不碰（补丁也不该覆盖它们）
        val ANDROID_OWNED = listOf(
            "include/subconv/android_http.hpp",
            "src/fetch/android_http.cpp",
        )

        const val DEFAULT_UPSTREAM_URL = "https://github.com/ycm50/sub-converter.git"
        val PATCH_FILE_RE = Regex("(?m)^diff --git a/(\\S+) b/")
        val CMAKE_SRC_RE = Regex("(?m)^\\s*(src/[A-Za-z0-9_/]+\\.cpp)\\s*$")
    }

    @TaskAction
    fun sync() {
        val cpp = cppDir.get().asFile
        if (!cpp.isDirectory) throw GradleException("被同步目录不存在：$cpp")
        val work = workDir.get().asFile.apply { mkdirs() }

        val pinned = if (ref.get().isBlank()) readPinned() else ref.get().trim()
        if (pinned.isEmpty()) {
            throw GradleException("既没给 -Psubconv.ref，${pinFile.files.joinToString { it.name }} 里也没有可用的 commit。")
        }
        if (pinned.any { it.isWhitespace() } || pinned.contains('#')) {
            throw GradleException("锚点不像一个 ref（含空白或 #）：'$pinned' —— 文件是不是被存成了 GBK/UTF-16，或者丢了换行？")
        }

        val repo = resolveRepo()
        val dry = dryRun.get()

        logger.lifecycle("subconv 同步上游")
        logger.lifecycle("  被同步目录: $cpp")
        logger.lifecycle("  上游仓库  : $repo")
        logger.lifecycle("  补丁      : ${patchList().size} 个" + if (patchList().isEmpty()) "  ⚠ 一个都没有，同步出来的树会和上游一模一样" else "")
        if (dry) logger.lifecycle("  模式      : DryRun（不写任何文件）")
        logger.lifecycle("")

        // --- 1. 解析 ref ---
        logger.lifecycle("== 解析 ref 并取出上游源码")
        val (revCode, revOut) = git(repo, listOf("rev-parse", "--verify", "$pinned^{commit}"))
        val commit = revOut.lineSequence().firstOrNull()?.trim().orEmpty()
        if (revCode != 0 || !commit.matches(Regex("^[0-9a-f]{40}$"))) {
            val hint = if (File(repo, ".git").isDirectory && upstream.get().isBlank()) {
                "\n  本地克隆里没有这个 ref —— 加 -Psubconv.fetch=true 先 fetch。"
            } else ""
            throw GradleException("解析不了 ref '$pinned'：$revOut$hint")
        }
        val (_, subjectOut) = git(repo, listOf("log", "-1", "--format=%h %s", commit))
        val subject = subjectOut.trim()
        logger.lifecycle("  commit: $commit")
        logger.lifecycle("  标题  : $subject")

        // 给 CI 留一份「这次到底同步了哪个上游 commit」的现场（job summary 会读它）。
        // 刻意不声明成 @OutputFile：这个任务必须每次都跑（上游动没动只有跑完才知道），
        // 一旦声明了 outputs，Gradle 就可能在输入没变时把整个任务跳过。
        if (!dry) {
            File(work, "last-sync.txt").writeText(
                buildString {
                    append("仓库  : $repo\n")
                    append("请求的 ref: $pinned\n")
                    append("commit    : $commit\n")
                    append("标题      : $subject\n")
                    append("同步到    : $cpp\n")
                    append("补丁      : ${patchList().joinToString(", ") { it.name }}\n")
                    append("时间      : ${LocalDateTime.now().withNano(0)}\n")
                },
                Charsets.UTF_8,
            )
        }

        // --- 2. 取源码（zip 自己解，不依赖系统 tar） ---
        val zip = File(work, "upstream.zip")
        if (zip.exists()) zip.delete()
        val (arcCode, arcOut) = git(repo, listOf("archive", "--format=zip", "-o", zip.absolutePath, commit))
        if (arcCode != 0) throw GradleException("git archive 失败（exit $arcCode）：$arcOut")
        val stage = File(work, "upstream")
        if (stage.exists()) stage.deleteRecursively()
        extractZip(zip, stage)

        val allFiles = relFiles(stage)
        val manifest = allFiles.filter { isUpstreamOwned(it) }
        logger.lifecycle("  上游文件: ${manifest.size} 个（整棵树 ${allFiles.size} 个；本工程只要清单内这些）")
        if (manifest.isEmpty()) {
            throw GradleException("清单内一个文件都没解出来，检查 -Psubconv.upstream / ref 是否指对了仓库。")
        }

        // --- 3. 比对 ---
        logger.lifecycle("")
        logger.lifecycle("== 比对 vendor 目录与上游")
        val cmp = compare(stage, cpp, manifest)
        val gone = relFiles(cpp)
            .filter { isUpstreamOwned(it) && !manifest.contains(it) }
            .sorted()

        logger.lifecycle("  新增 ${cmp.added.size} / 覆盖 ${cmp.updated.size} / 已一致 ${cmp.same} / 上游已无 ${gone.size}")
        cmp.added.forEach { logger.lifecycle("    + $it") }
        cmp.updated.forEach { logger.lifecycle("    M $it") }
        gone.forEach { logger.lifecycle("    - $it") }

        var patchFailures = listOf<String>()
        val expected = expectedPatchTargets()
        // 快路径：工作区已经就是「上游 + 补丁」的样子，那一个字都不用写。
        // 这不只是省事：覆盖写会改 mtime，而 include/subconv/server.hpp 是被到处 include 的头，
        // ninja 一看到它就把所有 TU 重编一遍。同步默认挂在构建上，所以这条快路径决定了
        // 日常构建（上游没动）不会平白来一次全量重编。
        val alreadyClean = !dry && cmp.added.isEmpty() && gone.isEmpty() &&
            cmp.updated.sorted() == expected.sorted()

        val drift: List<String>
        val leftover: List<String>
        if (dry) {
            logger.lifecycle("")
            logger.lifecycle("== DryRun：跳过写入与补丁")
            drift = (cmp.added + cmp.updated).sorted()
            leftover = emptyList()
        } else if (alreadyClean) {
            logger.lifecycle("")
            logger.lifecycle("== 已经就是「上游 + 补丁」的状态：跳过写入与套补丁（一个字节都不动）")
            drift = cmp.updated.sorted()
            leftover = emptyList()
        } else {
            // --- 4. 落盘：覆盖 + 删除 + 收空目录 ---
            logger.lifecycle("")
            logger.lifecycle("== 覆盖 vendor 目录")
            var n = 0
            (cmp.added + cmp.updated).forEach { rel ->
                val dst = File(cpp, rel)
                dst.parentFile?.mkdirs()
                File(stage, rel).copyTo(dst, overwrite = true)
                n++
            }
            gone.forEach { File(cpp, it).delete() }
            cleanupEmptyDirs(cpp)
            logger.lifecycle("  写入 $n 个文件，删除 ${gone.size} 个")

            // --- 5. 套补丁 ---
            logger.lifecycle("")
            logger.lifecycle("== 套用 patches/")
            patchFailures = applyPatches(cpp)

            // --- 6. 自检 ---
            val after = compare(stage, cpp, manifest)
            drift = (after.added + after.updated).sorted()
            leftover = after.added
        }

        if (!dry) {
            logger.lifecycle("")
            logger.lifecycle("== 自检：vendor 目录 vs 上游")
            logger.lifecycle("  与上游不同：${drift.size} 个（补丁覆盖：${expected.size} 个）")
            drift.forEach { logger.lifecycle("    M $it") }
            leftover.forEach { logger.lifecycle("    ? 上游有、本地没有：$it") }

            val onlyPatch = drift.filter { !expected.contains(it) }
            val unapplied = expected.filter { !drift.contains(it) }
            if (onlyPatch.isEmpty() && unapplied.isEmpty() && leftover.isEmpty()) {
                logger.lifecycle("  ✅ 差异恰好等于补丁集，同步干净")
            } else {
                if (unapplied.isNotEmpty()) logger.error("  ⚠ 补丁里的文件却和上游一致（补丁没生效？）：${unapplied.joinToString(", ")}")
                if (onlyPatch.isNotEmpty()) logger.error("  ⚠ 多出了补丁之外的差异（手工改过没进补丁？）：${onlyPatch.joinToString(", ")}")
                if (leftover.isNotEmpty()) logger.error("  ⚠ 上游有、本地没有的文件：${leftover.joinToString(", ")}")
            }
        }

        // --- 7. CMakeLists 源文件列表检查（只报警告，不自动改） ---
        logger.lifecycle("")
        logger.lifecycle("== 检查 CMakeLists.txt 的源文件列表")
        val cmakeFile = File(cpp, "CMakeLists.txt")
        val cmakeText = if (cmakeFile.isFile) cmakeFile.readText(Charsets.UTF_8) else ""
        val listed = CMAKE_SRC_RE.findAll(cmakeText).map { it.groupValues[1] }.toSortedSet()
        val upstreamCpp = manifest.filter { it.startsWith("src/") && it.endsWith(".cpp") }
        val needAdd = upstreamCpp.filter { !listed.contains(it) }
        val needDrop = listed.filter { !upstreamCpp.contains(it) && !ANDROID_OWNED.contains(it) }
        if (needAdd.isEmpty() && needDrop.isEmpty()) {
            logger.lifecycle("  一致：${upstreamCpp.size} 个上游 .cpp 都在列表里")
        } else {
            needAdd.forEach { logger.error("  ⚠ 上游新增的源文件没进 CMakeLists，会把链接搞崩：$it") }
            needDrop.forEach { logger.error("  ⚠ CMakeLists 里列了、但上游已经没有的源文件：$it") }
            logger.lifecycle("  请手工改 app/src/main/cpp/CMakeLists.txt 的 subconv_core 源文件列表（保持字母序）。")
        }
        val androidExtra = listed.filter { !upstreamCpp.contains(it) }
        logger.lifecycle("  CMakeLists 里 Android 自己加的源文件：${if (androidExtra.isEmpty()) "（无）" else androidExtra.joinToString(", ")}")

        // --- 8. 锚点前移 ---
        if (updatePin.get() && !dry) {
            logger.lifecycle("")
            logger.lifecycle("== 更新上游锚点")
            val target = pinFile.files.firstOrNull()
            if (target != null) {
                val text = buildString {
                    append("# 上游锚点（移植基线）\n")
                    append("#\n")
                    append("# syncUpstream 任务默认同步到这个 commit。改这一行 = 声明移植基线前移，\n")
                    append("# 改完请跑一次 ./gradlew syncUpstream 并把结果一起提交。\n")
                    append("#\n")
                    append("# 上一次同步：${LocalDate.now()}  $subject\n")
                    append("#\n")
                    append("$commit\n")
                }
                target.writeText(text, Charsets.UTF_8)
                logger.lifecycle("  写入 ${target.name} -> $commit")
            }
        }

        // --- 9. 收尾 ---
        logger.lifecycle("")
        logger.lifecycle("== 完成")
        if (dry) logger.lifecycle("  DryRun：什么都没改。")
        logger.lifecycle("  上游 ${commit.take(7)}  |  新增 ${cmp.added.size}  覆盖 ${cmp.updated.size}  删除 ${gone.size}")

        val problems = mutableListOf<String>()
        if (patchFailures.isNotEmpty()) problems += "补丁没套上：${patchFailures.joinToString(", ")}"
        // 严格模式（CI 用）：源文件列表不齐就直接失败。默认关 —— 平时它只是一条警告，
        // 但 CI 是「每次都拿上游最新」，上游新增 .cpp 是迟早的事，等到链接期才报
        // undefined reference，排查成本比这里红一条高得多。
        if (strict.get() && (needAdd.isNotEmpty() || needDrop.isNotEmpty())) {
            problems += "CMakeLists.txt 的源文件列表和上游对不上：${(needAdd + needDrop).joinToString(", ")}" +
                "（在 app/src/main/cpp/CMakeLists.txt 里手工加/删，保持字母序）"
        }
        if (!dry) {
            val onlyPatch = drift.filter { !expected.contains(it) }
            val unapplied = expected.filter { !drift.contains(it) }
            if (onlyPatch.isNotEmpty()) problems += "补丁之外的差异：${onlyPatch.joinToString(", ")}"
            if (unapplied.isNotEmpty()) problems += "补丁没生效：${unapplied.joinToString(", ")}"
        }
        if (problems.isNotEmpty()) {
            throw GradleException("同步结果不自洽 —— " + problems.joinToString("；") +
                "（补丁与上游冲突时按 patches/README.md 的「重新生成」重做补丁）")
        }
    }

    // -----------------------------------------------------------------------
    // 内部工具
    // -----------------------------------------------------------------------

    /**
     * 跑 git；repo 为 null 时就直接执行（用于 clone）。返回 exitCode 与合并后的输出。
     *
     * ceilingAt 用来给 git apply 兜住「仓库发现的边界」。vendor 目录（app/src/main/cpp）本身在
     * app 仓库里，而 git 一旦认出自己在某个 work tree 里，就把补丁路径当成「相对仓库根」解析，
     * 于是 app/src/main/cpp 里明明有 include/subconv/server.hpp，git 却会去仓库根的 include/ 找，
     * 找不到就当「路径在仓库外」静默忽略 —— exit 0、什么都不改，只在 stderr 打一句
     * `Skipped patch 'xxx'.`（这个坑在 subdir 下必然踩中）。把 GIT_CEILING_DIRECTORIES 指到
     * vendor 目录的上一级，git 就不再往上找 .git，git apply 退回 GNU patch 语义（相对当前目录），
     * 补丁才真的落盘。
     */
    private fun git(repo: File?, args: List<String>, ceilingAt: File? = null): Pair<Int, String> {
        val out = ByteArrayOutputStream()
        val err = ByteArrayOutputStream()
        val cmd = mutableListOf(gitExe.get())
        if (repo != null) {
            cmd += "-C"
            cmd += repo.absolutePath
        }
        cmd += args
        val result = execOps.exec {
            commandLine(cmd)
            isIgnoreExitValue = true
            standardOutput = out
            errorOutput = err
            if (ceilingAt != null) {
                environment("GIT_CEILING_DIRECTORIES", ceilingAt.absolutePath)
            }
        }
        return result.exitValue to (out.toString("UTF-8") + err.toString("UTF-8")).trim()
    }

    private fun readPinned(): String {
        val f = pinFile.files.firstOrNull { it.isFile } ?: return ""
        return f.readLines(Charsets.UTF_8)
            .map { it.trim().trimStart('\uFEFF').trim() }
            .firstOrNull { it.isNotEmpty() && !it.startsWith("#") }
            .orEmpty()
    }

    private fun resolveRepo(): File {
        val raw = upstream.get().trim()
        if (raw.isNotEmpty()) {
            val f = File(raw)
            if (f.isDirectory) {
                if (doFetch.get()) {
                    val (rc, out) = git(f, listOf("fetch", "--all", "--tags", "--prune"))
                    if (rc != 0) throw GradleException("git fetch 失败（exit $rc）：$out")
                }
                return f
            }
            if (!looksLikeUrl(raw)) {
                throw GradleException("-Psubconv.upstream 指向的路径不存在，也不像个 URL：$raw")
            }
            return ensureClone(raw)
        }
        val sibling = siblingUpstream.get().asFile
        if (sibling.isDirectory) return sibling
        logger.lifecycle("  本机没有上游克隆（$sibling），改用 $DEFAULT_UPSTREAM_URL")
        return ensureClone(DEFAULT_UPSTREAM_URL)
    }

    private fun looksLikeUrl(s: String): Boolean =
        s.contains("://") || s.startsWith("git@") || s.endsWith(".git")

    private fun ensureClone(url: String): File {
        val cache = cloneCache.get().asFile
        if (File(cache, ".git").isDirectory) {
            if (doFetch.get()) {
                val (rc, out) = git(cache, listOf("fetch", "--all", "--tags", "--prune"))
                if (rc != 0) throw GradleException("git fetch 失败（exit $rc）：$out")
                logger.lifecycle("  已更新上游缓存：$cache")
            }
            return cache
        }
        cache.parentFile?.mkdirs()
        if (cache.exists()) cache.deleteRecursively()
        logger.lifecycle("  克隆上游：$url -> $cache")
        val (rc, out) = git(null, listOf("clone", "--quiet", url, cache.absolutePath))
        if (rc != 0) throw GradleException("git clone 失败（exit $rc）：$out")
        return cache
    }

    private fun patchList(): List<File> =
        patchFiles.files.filter { it.isFile && it.name.endsWith(".patch") }.sortedBy { it.name }

    private fun applyPatches(cpp: File): List<String> {
        val failed = mutableListOf<String>()
        // 钉死换行：git apply 会按 core.autocrlf / eol 属性把内容"检出"一遍，不钉的话
        // 在 Windows 上会把补丁落成 CRLF；仓库里是 LF，一个字节不同也算差异，自检就会报。
        val cfg = listOf("-c", "core.autocrlf=false", "-c", "core.eol=lf")
        // 补丁路径是相对 vendor 目录的，必须让 git 别把 app 仓库当上下文（见 git() 的注释）。
        val ceiling = cpp.canonicalFile.parentFile ?: cpp.canonicalFile
        patchList().forEach { p ->
            val (checkCode, checkOut) = git(cpp, cfg + listOf("apply", "-p1", "--check", p.absolutePath), ceiling)
            if (checkCode == 0) {
                val (applyCode, applyOut) = git(cpp, cfg + listOf("apply", "-p1", p.absolutePath), ceiling)
                if (applyCode == 0) {
                    logger.lifecycle("  OK   ${p.name}")
                } else {
                    logger.error("  FAIL ${p.name}：$applyOut")
                    failed += p.name
                }
            } else if (reject.get()) {
                val (_, rejOut) = git(cpp, cfg + listOf("apply", "-p1", "--reject", p.absolutePath), ceiling)
                logger.lifecycle("  REJ  ${p.name}（套不上的落 .rej，请人工处理）")
                if (rejOut.isNotEmpty()) logger.lifecycle(rejOut)
                failed += p.name
            } else {
                logger.error("  FAIL ${p.name}：套不上（上游动过这块）")
                if (checkOut.isNotEmpty()) logger.error(checkOut)
                failed += p.name
            }
        }
        return failed
    }

    /** 补丁覆盖了哪些文件 —— 自检时的「期望差异」。 */
    private fun expectedPatchTargets(): List<String> =
        patchList()
            .flatMap { p -> PATCH_FILE_RE.findAll(p.readText(Charsets.UTF_8)).map { it.groupValues[1] } }
            .distinct()
            .sorted()

    private data class Cmp(val added: List<String>, val updated: List<String>, val same: Int)

    private fun compare(stage: File, cpp: File, manifest: List<String>): Cmp {
        val added = mutableListOf<String>()
        val updated = mutableListOf<String>()
        var same = 0
        manifest.forEach { rel ->
            val a = File(cpp, rel)
            if (!a.isFile) {
                added += rel
            } else if (sha256(a) != sha256(File(stage, rel))) {
                updated += rel
            } else {
                same++
            }
        }
        return Cmp(added.sorted(), updated.sorted(), same)
    }

    /** 上游删了文件后可能留下空目录，顺手收掉（只收上游目录范围内的）。 */
    private fun cleanupEmptyDirs(cpp: File) {
        UPSTREAM_DIRS.forEach { d ->
            val root = File(cpp, d)
            if (!root.isDirectory) return@forEach
            // 先收成列表再删：删目录时还在遍历它的父节点，边遍历边删容易踩到已消失的路径
            root.walkBottomUp()
                .filter { it.isDirectory && it != root }
                .toList()
                .filter { it.list()?.isEmpty() ?: false }
                .forEach { it.delete() }
        }
    }

    // 自己解 zip。
    //
    // 不用 zipTree + copy：Gradle 会给拷贝套上「默认排除」，.gitignore / .gitattributes
    // 这类点文件会被悄悄丢掉（整棵树 72 → 70）。这俩本来不在清单里，丢不丢不影响同步结果，
    // 但「顺手少两个文件」这种行为不值得留着——将来上游要是把什么点文件放进目录里，
    // 这套毛病会以最难查的方式出现。
    //
    // 注意：这里别写成 /* 开头的 KDoc，Kotlin 的块注释会嵌套，正文里的 glob 通配（星号接斜杠）
    // 会被当成注释结束，报一堆「Expecting member declaration」。
    private fun extractZip(zip: File, dest: File) {
        dest.mkdirs()
        val prefix = dest.canonicalPath.trimEnd(File.separatorChar) + File.separator
        ZipFile(zip).use { zf ->
            zf.entries().asSequence().forEach { e ->
                val target = File(dest, e.name)
                // zip-slip：归档里的路径可能带 ../，别让它写出 dest 之外
                if (!target.canonicalPath.startsWith(prefix)) {
                    throw GradleException("上游归档里有越界路径，拒绝解包：${e.name}")
                }
                if (e.isDirectory) {
                    target.mkdirs()
                } else {
                    target.parentFile?.mkdirs()
                    zf.getInputStream(e).use { input -> target.outputStream().use { input.copyTo(it) } }
                }
            }
        }
    }

    private fun isUpstreamOwned(rel: String): Boolean {
        if (ANDROID_OWNED.contains(rel)) return false
        if (UPSTREAM_DIRS.any { rel == it || rel.startsWith("$it/") }) return true
        return UPSTREAM_FILES.contains(rel)
    }

    private fun relFiles(root: File): List<String> {
        if (!root.isDirectory) return emptyList()
        return root.walkTopDown()
            .filter { it.isFile }
            .map { it.relativeTo(root).invariantSeparatorsPath }
            .sorted()
            .toList()
    }

    private fun sha256(f: File): String =
        MessageDigest.getInstance("SHA-256").digest(f.readBytes()).joinToString("") { "%02x".format(it) }
}

// ---------------------------------------------------------------------------
// verifyKernel：核对 APK 里确实有那三份 .so，且没有漏出来的 libc++_shared.so
//
// 这几个错都是「编过了、装到手机上才炸」的类型，放在 CI 里最划算。
// 它不触发构建（不依赖 assemble*），直接看现成的 APK；没打就先跑 assemble。
// ---------------------------------------------------------------------------
abstract class VerifyKernelTask : DefaultTask() {

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val apkCandidates: ConfigurableFileCollection

    @get:InputFile
    @get:PathSensitive(PathSensitivity.NONE)
    abstract val appGradleFile: RegularFileProperty

    @get:Input
    abstract val expectedAbis: ListProperty<String>

    @TaskAction
    fun verify() {
        val apk = apkCandidates.files.filter { it.isFile }.maxByOrNull { it.lastModified() }
            ?: throw GradleException("没找到现成的 APK（找过 ${apkCandidates.files.joinToString { it.name }}）。先跑 ./gradlew :app:assembleDebug。")

        // abiFilters 是唯一的真相来源，别在别处再写一份
        val gradleText = appGradleFile.get().asFile.readText(Charsets.UTF_8)
        val fromGradle = Regex("abiFilters\\s*\\+=\\s*listOf\\(([^)]*)\\)")
            .find(gradleText)?.groupValues?.get(1)
            ?.split(',')?.map { it.trim().trim('"') }?.filter { it.isNotEmpty() }
        val abis = fromGradle?.takeIf { it.isNotEmpty() } ?: expectedAbis.get()

        logger.lifecycle("subconv 内核校验")
        logger.lifecycle("  APK : $apk")
        logger.lifecycle("  ABI : ${abis.joinToString(", ")}")

        val entries = ZipFile(apk).use { zip -> zip.entries().asSequence().map { it.name }.toList() }
        val libs = entries.filter { it.startsWith("lib/") && it.endsWith(".so") }

        var bad = false
        abis.forEach { abi ->
            val want = "lib/$abi/libsubconv.so"
            if (libs.contains(want)) {
                logger.lifecycle("  OK   $want")
            } else {
                logger.error("  FAIL 缺 $want")
                bad = true
            }
        }
        val leaked = libs.filter { it.endsWith("libc++_shared.so") }
        if (leaked.isEmpty()) {
            logger.lifecycle("  OK   没有 libc++_shared.so（libc++ 是静态链进去的）")
        } else {
            logger.error("  FAIL APK 里出现了 ${leaked.joinToString(", ")} —— ANDROID_STL 不是 c++_static？")
            bad = true
        }
        val unexpected = libs.filter { it.endsWith(".so") && !it.endsWith("libsubconv.so") }
        if (unexpected.isNotEmpty()) logger.lifecycle("  其他 .so：${unexpected.joinToString(", ")}")

        if (bad) throw GradleException("APK 里的原生库不对：$apk")
        logger.lifecycle("  全部通过。")
    }
}

// ---------------------------------------------------------------------------
// 注册任务
// ---------------------------------------------------------------------------
fun ProviderFactory.subconvProp(name: String, default: String = "") =
    gradleProperty(name).orElse(default)

fun ProviderFactory.subconvFlag(name: String) =
    gradleProperty(name).map { it.equals("true", ignoreCase = true) || it == "1" }.orElse(false)

/** 同上，但默认是「开」—— 传 -Pxxx=false 才关。 */
fun ProviderFactory.subconvFlagDefaultOn(name: String) =
    gradleProperty(name).map { it.equals("true", ignoreCase = true) || it == "1" }.orElse(true)

val subconvCppDir = providers.gradleProperty("subconv.cppDir")
    .map { layout.projectDirectory.dir(it) }
    .orElse(layout.projectDirectory.dir("app/src/main/cpp"))

val subconvPatches = layout.projectDirectory.dir("patches").asFileTree.matching { include("*.patch") }

tasks.register<SyncUpstreamTask>("syncUpstream") {
    group = "subconv"
    description = "拉上游源码 + 自动套 patches/ 里的 Android 适配补丁 + 自检（默认同步到 tools/upstream-ref.txt 的锚点）"

    pinFile.from(layout.projectDirectory.file("tools/upstream-ref.txt"))
    patchFiles.from(subconvPatches)
    cppDir.set(subconvCppDir)
    siblingUpstream.set(layout.projectDirectory.dir("../sub-converter"))
    workDir.set(layout.buildDirectory.dir("upstream-sync"))
    cloneCache.set(layout.buildDirectory.dir("upstream-cache"))

    ref.set(providers.subconvProp("subconv.ref"))
    upstream.set(providers.subconvProp("subconv.upstream"))
    gitExe.set(providers.subconvProp("subconv.git", "git"))
    dryRun.set(providers.subconvFlag("subconv.dryRun"))
    doFetch.set(providers.subconvFlag("subconv.fetch"))
    reject.set(providers.subconvFlag("subconv.reject"))
    updatePin.set(providers.subconvFlag("subconv.updatePin"))
    strict.set(providers.subconvFlag("subconv.strict"))
}

tasks.register<VerifyKernelTask>("verifyKernel") {
    group = "subconv"
    description = "核对 APK 里三个 ABI 的 libsubconv.so 都在，且没有 libc++_shared.so（先跑 assemble）"

    apkCandidates.from(
        layout.projectDirectory.dir("app/build/outputs/apk").asFileTree.matching { include("**/*.apk") }
    )
    appGradleFile.set(layout.projectDirectory.file("app/build.gradle.kts"))
    expectedAbis.set(
        providers.gradleProperty("subconv.abis")
            .map { it.split(',').map { s -> s.trim() }.filter { s -> s.isNotEmpty() } }
            .orElse(listOf("arm64-v8a", "armeabi-v7a", "x86_64"))
    )
}

// ---------------------------------------------------------------------------
// 构建即同步：让 :app 的构建任务先依赖 syncUpstream，
// 于是 ./gradlew :app:assembleRelease 本身就是 pull → 套补丁 → 编内核 → .so 进 APK。
//
// 挂两类任务，缺一不可：
//   * preBuild / preDebugBuild / preReleaseBuild —— 每个 variant 的第一个任务，
//     是唯一能保证「在一切之前」的挂点；
//   * 真正的 native 任务（externalNativeBuild* / configureCMake* / buildCMake*）——
//     assembleDebug 是直接从按 ABI 拆的 buildCMakeDebug[abi] 走过来的，**不经过**
//     externalNativeBuildDebug（实测：只挂后者的话，assembleDebug 的图里根本没有该任务，
//     同步就变成「写了不跑」）。挂 preBuild 是主保险，这几条是明示意图。
//     构建类型名是拼进任务名的：debug 是 Debug，release 走的是 RelWithDebInfo
//     （configureCMakeRelWithDebInfo[abi]），所以这里要列全 —— 更不能写成
//     「configureCMake*」通配，那会把 externalNativeBuildClean* 也捞进来，
//     变成「clean 之前先拉一遍上游」。
//
// 不挂别的（不挂 assemble*/lint/test）：同步的语义是「编内核之前把源码准备好」，
// 不是「任何 Gradle 命令都去碰上游」。实测 clean 的图里没有 :syncUpstream。
//
// 依赖写成任务路径字符串（":syncUpstream"），不从子工程里抓 rootProject 的 Task 对象：
// 配置缓存下前者安全，后者会在 execution 期碰到 project。
//
// 关掉：-Psubconv.syncOnBuild=false（离线时，或者只想编当前工作区、别动上游时）。
// ---------------------------------------------------------------------------
val subconvSyncOnBuild = providers.subconvFlagDefaultOn("subconv.syncOnBuild")
val subconvSyncAnchor = Regex(
    "^pre(?:[A-Za-z]*)?Build$" +
        "|^(?:externalNativeBuild(?:Debug|Release)|(?:configure|build)CMake(?:Debug|Release|RelWithDebInfo))(?:\\[[^\\]]+\\])?$"
)

project(":app").tasks
    .matching { subconvSyncAnchor.matches(it.name) }
    .configureEach {
        if (subconvSyncOnBuild.get()) dependsOn(":syncUpstream")
    }
