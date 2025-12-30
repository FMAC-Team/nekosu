package me.neko.nksu.util

import android.content.Context
import android.util.Log
import java.io.RandomAccessFile
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

object SigCheck {

    private const val DEBUG_EXPECTED_SIGNATURE = "1692015C04AA6CEA61B9E3FBF6CBC9FA5933E6A6A5788C12D1289A6D9E51D45E"
    private const val RELEASE_EXPECTED_SIGNATURE = "1C9CEAC6A82DE20EF909103926C296B2882653B4C9189360FCA9F081FCD663B1"
    
    private const val TAG = "SigCheck"

    private val APK_SIGNING_BLOCK_MAGIC = byteArrayOf(
        0x41, 0x50, 0x4b, 0x20, 0x53, 0x69, 0x67, 0x20,
        0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x20, 0x34, 0x32
    )

    private const val APK_SIGNATURE_SCHEME_V2_BLOCK_ID = 0x7109871a
    private const val APK_SIGNATURE_SCHEME_V3_BLOCK_ID = 0xf05368c0.toInt()

    fun validate(context: Context): Boolean {
        var raf: RandomAccessFile? = null
        try {
            val apkPath = context.applicationInfo.sourceDir
            raf = RandomAccessFile(apkPath, "r")

            val signatureInfo = findApkSigningBlock(raf)
            if (signatureInfo == null) {
                Log.e(TAG, "未找到 APK Signing Block。应用可能仅使用了 V1 签名，或者已被篡改。")
                return false
            }

            val v3Block = findBlockById(signatureInfo, APK_SIGNATURE_SCHEME_V3_BLOCK_ID)
            val v2Block = findBlockById(signatureInfo, APK_SIGNATURE_SCHEME_V2_BLOCK_ID)

            val targetBlock = v3Block ?: v2Block
            if (targetBlock == null) {
                Log.e(TAG, "未找到 V2 或 V3 签名块。禁止仅使用 V1 签名的应用运行。")
                return false
            }

            val certs = parseCertificatesFromBlock(targetBlock)
            if (certs.isEmpty()) {
                Log.e(TAG, "签名块解析失败或未包含证书。")
                return false
            }

            for (certBytes in certs) {
                val currentSignature = getSHA256(certBytes)
                 Log.d(TAG, "Found Signature: $currentSignature")
                if (DEBUG_EXPECTED_SIGNATURE == currentSignature|| RELEASE_EXPECTED_SIGNATURE == currentSignature) {
                    return true
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "签名校验严重错误: ${e.message}")
        } finally {
            try { raf?.close() } catch (e: Exception) {}
        }
        return false
    }

    private fun findBlockById(signingBlock: ByteBuffer, blockId: Int): ByteBuffer? {
       
        val buffer = signingBlock.duplicate()
        buffer.order(ByteOrder.LITTLE_ENDIAN)
        
        while (buffer.remaining() >= 8) {
            val len = buffer.long
            if (len < 4 || len > buffer.remaining()) break 

            val nextId = buffer.int
            val valueLen = (len - 4).toInt()
            
            if (nextId == blockId) {
                val valueLimit = buffer.position() + valueLen
                val valueBuffer = buffer.duplicate()
                valueBuffer.limit(valueLimit)
                return valueBuffer
            }
            
            buffer.position(buffer.position() + valueLen)
        }
        return null
    }

    private fun parseCertificatesFromBlock(blockBuffer: ByteBuffer): List<ByteArray> {
        val certs = ArrayList<ByteArray>()
        try {
            blockBuffer.order(ByteOrder.LITTLE_ENDIAN)

            val signersBuffer = getLengthPrefixedSlice(blockBuffer)

            while (signersBuffer.hasRemaining()) {
                val signerBuffer = getLengthPrefixedSlice(signersBuffer)

                val signedDataBuffer = getLengthPrefixedSlice(signerBuffer)

                val digestsLen = signedDataBuffer.int 
                signedDataBuffer.position(signedDataBuffer.position() + digestsLen) 

                val certificatesBuffer = getLengthPrefixedSlice(signedDataBuffer)

            
                while (certificatesBuffer.hasRemaining()) {
                    val certLen = certificatesBuffer.int
                    val certBytes = ByteArray(certLen)
                    certificatesBuffer.get(certBytes)
                    certs.add(certBytes)
                }
            }
        } catch (e: Exception) {
           
        }
        return certs
    }


    private fun getLengthPrefixedSlice(buffer: ByteBuffer): ByteBuffer {
        val len = buffer.int
        if (len < 0) throw IllegalArgumentException("Negative length")
        val limit = buffer.position() + len
        val slice = buffer.duplicate()
        slice.limit(limit)
        buffer.position(limit)
        slice.order(ByteOrder.LITTLE_ENDIAN)
        return slice
    }

    private fun findApkSigningBlock(raf: RandomAccessFile): ByteBuffer? {

        val eocdOffset = findEOCD(raf)
        if (eocdOffset == -1L) return null

        raf.seek(eocdOffset + 16)
        val centralDirOffset = Integer.reverseBytes(raf.readInt()).toLong() and 0xFFFFFFFFL

        val magicOffset = centralDirOffset - 16
        if (magicOffset < 0) return null

        raf.seek(magicOffset)
        val magicBuf = ByteArray(16)
        raf.readFully(magicBuf)
        if (!magicBuf.contentEquals(APK_SIGNING_BLOCK_MAGIC)) {
            return null // 不是 V2/V3 签名
        }


        raf.seek(magicOffset - 8)
        val blockSize = java.lang.Long.reverseBytes(raf.readLong())
        val sizeHeaderOffset = centralDirOffset - (blockSize + 8)
        if (sizeHeaderOffset < 0) return null

        val pairsSize = (blockSize - 24).toInt()
        if (pairsSize < 0) return null

        val pairsBuffer = ByteArray(pairsSize)
        raf.seek(sizeHeaderOffset + 8)
        raf.readFully(pairsBuffer)

        return ByteBuffer.wrap(pairsBuffer)
    }

    private fun findEOCD(raf: RandomAccessFile): Long {
        val fileLen = raf.length()
        if (fileLen < 22) return -1
        
        val range = 65535 + 22
        val scanLen = if (fileLen < range) fileLen else range.toLong()
        
        val buffer = ByteArray(scanLen.toInt())
        val startPos = fileLen - scanLen
        raf.seek(startPos)
        raf.readFully(buffer)
        for (i in buffer.size - 22 downTo 0) {
            if (buffer[i] == 0x50.toByte() &&
                buffer[i + 1] == 0x4B.toByte() &&
                buffer[i + 2] == 0x05.toByte() &&
                buffer[i + 3] == 0x06.toByte()) {
                return startPos + i
            }
        }
        return -1
    }

    private fun getSHA256(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(data)
        return hash.joinToString("") { "%02X".format(it) }
    }
}