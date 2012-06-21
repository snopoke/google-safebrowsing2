package net.google.safebrowsing2.parsers

import scala.util.parsing.combinator._
import scala.util.parsing.input.{ Position, Reader }
import scala.util.parsing.input.CharArrayReader.EofCh
import scala.annotation.tailrec
import java.lang.Float.intBitsToFloat
import java.lang.Double.longBitsToDouble
import util.Helpers._
import java.io.EOFException

/**
 * @see http://www.scala-lang.org/node/4693
 */
trait ParsersUtil extends Parsers {
  lazy val anyElem: Parser[Elem] = elem("anyElem", _ => true)
  def elemExcept(xs: Elem*): Parser[Elem] = elem("elemExcept", x => !(xs contains x))
  def elemOf(xs: Elem*): Parser[Elem] = elem("elemOf", xs contains _)

  def take(n: Int): Parser[Seq[Elem]] = repN(n, anyElem)
  def takeUntil(cond: Parser[Elem]): Parser[Seq[Elem]] = takeUntil(cond, anyElem)
  def takeUntil(cond: Parser[Elem], p: Parser[Elem]): Parser[Seq[Elem]] = rep(not(cond) ~> p)
  def takeWhile(p: Parser[Elem]): Parser[Seq[Elem]] = rep(p)
}

case class ByteOffsetPosition(offset: Int) extends Position {
  final val line = 1
  def column = offset + 1
  def lineContents: String = ""
}

class ByteReader(val bytes: Array[Byte], override val offset: Int) extends Reader[Byte] {
  def this(reader: Reader[_]) = this(reader.source.toString.getBytes, 0)
  def this(bytes: Seq[Byte]) = this(bytes.toArray, 0)
  def this(str: String) = this(str.getBytes, 0)

  def first: Byte = {
    if (offset < bytes.length) {
      bytes(offset)
    } else {
      throw new EOFException
    }
  }

  def rest: ByteReader = if (atEnd) this else new ByteReader(bytes, offset + 1)
  def pos: Position = ByteOffsetPosition(offset)
  def atEnd = offset >= bytes.length

  def byteAt(n: Int) = bytes(n)
  def length = bytes.length - offset

  override def drop(n: Int): ByteReader = new ByteReader(bytes, offset + n)
  def take(n: Int): Seq[Byte] = bytes drop offset take n

  override def toString = "ByteReader(%d / %d)".format(offset, bytes.length)
}

trait BinaryParsers extends Parsers with ParsersUtil {
  type Elem = Byte

  protected implicit def readerToByteReader(x: Input): ByteReader = x match {
    case br: ByteReader => br
    case _ => new ByteReader(x)
  }
  
  override def acceptIf(p: Elem => Boolean)(err: Elem => String): Parser[Elem] = Parser { in =>
    try {
      if (p(in.first)) {
        Success(in.first, in.rest)
      } else {
        Failure(err(in.first), in)
      }
    } catch {
      case e: EOFException => Failure("EOF unexpected", in)
    }
  }
  
  override def acceptMatch[U](expected: String, f: PartialFunction[Elem, U]): Parser[U] = Parser{ in =>
    try {
      if (f.isDefinedAt(in.first)) {
        Success(f(in.first), in.rest)
      } else {
        Failure(expected + " expected", in)
      }
    } catch {
      case e: EOFException => Failure("EOF unexpected: " + expected + " expected", in)
    }
  }
  def toInt(bytes: Seq[Byte]): Int = bytes.foldLeft(0)((x, b) => (x << 8) + (b & 0xFF))
  def toLong(bytes: Seq[Byte]): Long = bytes.foldLeft(0L)((x, b) => (x << 8) + (b & 0xFF))
  def toString(bytes: Seq[Byte]): String = new String(bytes.toArray)
  def toHex(bytes: Seq[Byte]): String = bytes2Hex(bytes) 
  def asciiInt(byte: Seq[Byte]): Int = toString(byte).toInt

  lazy val byte: Parser[Byte] = anyElem
  lazy val u1: Parser[Int] = byte ^^ (_ & 0xFF)
  lazy val u2: Parser[Int] = bytes(2) ^^ toInt
  lazy val u4: Parser[Int] = bytes(4) ^^ toInt
  lazy val u4f: Parser[Float] = u4 ^^ intBitsToFloat
  lazy val u8: Parser[Long] = bytes(8) ^^ toLong
  lazy val u8d: Parser[Double] = u8 ^^ longBitsToDouble

  def bytes(n: Int): Parser[Seq[Byte]] = Parser { in =>
    if (n <= in.length) Success(in take n, in drop n)
    else Failure("Requested %d bytes but only %d remain".format(n, in.length), in)
  }
  
  override def phrase[T](p: Parser[T]): Parser[T] =
    super.phrase(p <~ opt(elem(EofCh)))

  /** Parse all of character sequence `in` with parser `p`. */
  def parseAll[T](p: Parser[T], in: Input): ParseResult[T] =
    parse(phrase(p), in)
  def parse[T](p: Parser[T], in: Input): ParseResult[T] = p(in)
  def parseAll[T](p: Parser[T], in: String): ParseResult[T] = parseAll(p, new ByteReader(in))
}