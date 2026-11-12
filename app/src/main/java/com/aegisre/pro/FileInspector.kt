package com.aegisre.pro
import java.security.MessageDigest
data class GeneralFileInfo(val name:String,val extension:String,val sizeBytes:Int,val detectedType:String,val sha256:String,val isProbablyText:Boolean,val textPreview:String,val hexPreview:String)
object FileInspector {
 fun inspect(name:String,bytes:ByteArray):GeneralFileInfo {
  val sample=bytes.take(4096).toByteArray()
  val ext=name.substringAfterLast('.', "").lowercase().take(16)
  val text=sample.none { val c=it.toInt() and 255; c==0 || c<9 || c in 14..31 }
  val type=when {
   bytes.starts(0x50,0x4b,0x03,0x04)->"ZIP archive / APK container"
   bytes.starts(0x7f,0x45,0x4c,0x46)->"ELF executable / shared library"
   bytes.starts(0x89,0x50,0x4e,0x47)->"PNG image"
   bytes.starts(0xff,0xd8,0xff)->"JPEG image"
   bytes.starts(0x25,0x50,0x44,0x46)->"PDF document"
   bytes.starts(0x64,0x65,0x78,0x0a)->"Android DEX bytecode"
   ext in setOf("kt","java","xml","json","txt","md","gradle","kts","py","js")->"Text / source file"
   else->"Unknown / binary file"
  }
  val hash=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(""){"%02x".format(it)}
  return GeneralFileInfo(name,ext,bytes.size,type,hash,text,if(text) sample.toString(Charsets.UTF_8).replace("\u0000","�") else "",sample.take(128).joinToString(" "){"%02X".format(it)})
 }
 private fun ByteArray.starts(vararg values:Int)=size>=values.size && values.indices.all{(this[it].toInt() and 255)==values[it]}
}
