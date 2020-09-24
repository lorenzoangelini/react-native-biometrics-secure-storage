package com.reactnativebiometricssecurestorage

object FileUtils {
  /**
   * Write string with encoding to file
   *
   * @param path Destination file path.
   */
  @kotlin.jvm.Throws(IOException::class)
  fun writeFile(path: String, bytes: ByteArray?) {
    try {
      val f: java.io.File = java.io.File(path)
      val dir: java.io.File = f.getParentFile()
      if (!f.exists()) {
        if (dir != null && !dir.exists()) {
          if (!dir.mkdirs()) {
            throw IOException("Failed to create parent directory of '$path'")
          }
        }
        if (!f.createNewFile()) {
          throw IOException("File '$path' does not exist and could not be created")
        }
      }
      val fout = FileOutputStream(f, false)
      try {
        fout.write(bytes)
      } finally {
        fout.close()
      }
    } catch (e: FileNotFoundException) {
      throw IOException("File '$path' does not exist and could not be created, or it is a directory")
    } catch (e: java.lang.Exception) {
      throw IOException(e.getLocalizedMessage())
    }
  }

  /**
   * Read file with a buffer that has the same size as the target file.
   *
   * @param path Path of the file.
   */
  @kotlin.jvm.Throws(IOException::class)
  fun readFile(path: String): ByteArray {
    var path = path
    val resolved = path
    if (resolved != null) path = resolved
    return try {
      val bytes: ByteArray
      val bytesRead: Int
      val length: Int
      val f: java.io.File = java.io.File(path)
      length = f.length()
      bytes = ByteArray(length)
      val `in` = FileInputStream(f)
      bytesRead = `in`.read(bytes)
      `in`.close()
      if (bytesRead < length) {
        throw IOException("Read only $bytesRead bytes of $length")
      }
      bytes
    } catch (err: FileNotFoundException) {
      val msg: String = err.getLocalizedMessage()
      if (msg.contains("EISDIR")) {
        throw IOException("Expecting a file but '$path' is a directory; $msg")
      } else {
        throw IOException("No such file '$path'; $msg")
      }
    } catch (err: java.lang.Exception) {
      throw IOException(err.getLocalizedMessage())
    }
  }
}
