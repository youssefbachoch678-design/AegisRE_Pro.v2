package com.aegisre.pro
data class CodeDiagnostic(val line:Int,val message:String)
/** Checks balanced delimiters only; this is not a compiler or full language linter. */
object CodeDiagnostics {
 fun checkDelimiters(source:String):List<CodeDiagnostic> {
  val stack=ArrayDeque<Pair<Char,Int>>()
  val pairs=mapOf(')' to '(' , ']' to '[' , '}' to '{')
  var line=1; var quote=0; var escaped=false; var lineComment=false; var blockComment=false; var i=0
  while(i<source.length) {
   val c=source[i]; val next=source.getOrNull(i+1)
   if(c=='\n'){line++;lineComment=false;i++;continue}
   if(lineComment){i++;continue}
   if(blockComment){if(c=='*' && next=='/'){blockComment=false;i+=2}else i++;continue}
   if(quote!=0){if(escaped)escaped=false else if(c.code==92)escaped=true else if(c.code==quote)quote=0;i++;continue}
   if(c=='/' && next=='/'){lineComment=true;i+=2;continue}
   if(c=='/' && next=='*'){blockComment=true;i+=2;continue}
   if(c.code==34 || c.code==39){quote=c.code;i++;continue}
   if(c=='(' || c=='[' || c=='{')stack.addLast(c to line)
   else if(c in pairs){if(stack.isEmpty() || stack.last().first!=pairs[c])return listOf(CodeDiagnostic(line,"Unexpected closing delimiter"));stack.removeLast()}
   i++
  }
  if(quote!=0)return listOf(CodeDiagnostic(line,"String or character literal is not closed"))
  if(blockComment)return listOf(CodeDiagnostic(line,"Block comment is not closed"))
  return stack.map{CodeDiagnostic(it.second,"Opening delimiter has no matching close")}
 }
}
