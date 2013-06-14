/* 
 * Copyright 2012 Simon Kelly
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *    http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package net.google.safebrowsing2
import org.junit.Test
import org.junit.Assert._
import org.hamcrest.CoreMatchers._
import org.scalatest.mock.MockitoSugar
import java.net.URL

class ExpressionGeneratorTests extends MockitoSugar with ByteUtil {

  val eb = new ExpressionGenerator("http://www.google.com")

  @Test
  def testMakeHostKey = {
    val domain = eb.makeHostKeys("www.google.com")
    assertThat(domain(0), is("google.com/"))
    assertThat(domain(1), is("www.google.com/"))
  }

  @Test
  def testMakeHostKey_short = {
    val domain = eb.makeHostKeys("google.com")
    assertThat(domain(0), is("google.com/"))
  }

  @Test
  def testMakeHostKey_long = {
    val domain = eb.makeHostKeys("malware.testing.google.test")
    assertThat(domain(0), is("google.test/"))
    assertThat(domain(1), is("testing.google.test/"))
  }

  @Test
  def testMakeHostKey_ip = {
    val domain = eb.makeHostKeys("127.0.0.1")
    assertThat(domain.size, is(1))
    assertThat(domain(0), is("127.0.0.1"))
  }

  @Test
  def testMakeHostList_long = {
    val domains = eb.makeHostList("a.b.c.d.e.f.g")
    assertThat(domains.size, is(5))
    assertTrue(domains.contains("a.b.c.d.e.f.g"))
    assertTrue(domains.contains("c.d.e.f.g"))
    assertTrue(domains.contains("d.e.f.g"))
    assertTrue(domains.contains("e.f.g"))
    assertTrue(domains.contains("f.g"))
  }

  @Test
  def testMakeHostList_short = {
    val domains = eb.makeHostList("d.e.f.g")
    assertThat(domains.size, is(3))
    assertTrue(domains.contains("d.e.f.g"))
    assertTrue(domains.contains("e.f.g"))
    assertTrue(domains.contains("f.g"))
  }

  @Test
  def testMakePathList = {
    val paths = eb.makePathList(new URL("http://test.com/1/2.html?param=1"))
    assertThat(paths.size, is(4))
    assertTrue(paths.contains("/1/2.html?param=1"))
    assertTrue(paths.contains("/1/2.html"))
    assertTrue(paths.contains("/1/"))
    assertTrue(paths.contains("/"))
  }

  @Test
  def testMakePathList_trailingSlash = {
    val paths = eb.makePathList(new URL("http://test.com/1/2/"))
    assertThat(paths.size, is(3))
    assertTrue(paths.contains("/1/2/"))
    assertTrue(paths.contains("/1/"))
    assertTrue(paths.contains("/"))
  }

  @Test
  def testMakePathList_empty = {
    val paths = eb.makePathList(new URL("http://test.com/"))
    assertThat(paths.size, is(1))
    assertTrue(paths.contains("/"))
  }

  @Test
  def testMakePathList_long = {
    val paths = eb.makePathList(new URL("http://test.com/1/2/3/4/5/6/7/a.html?param=1"))
    assertThat(paths.size, is(6))
    assertTrue(paths.contains("/1/2/3/4/5/6/7/a.html?param=1"))
    assertTrue(paths.contains("/1/2/3/4/5/6/7/a.html"))
    assertTrue(paths.contains("/1/2/3/"))
    assertTrue(paths.contains("/1/2/"))
    assertTrue(paths.contains("/1/"))
    assertTrue(paths.contains("/"))
  }

  @Test
  def testExpression = {
    val e = Expression("a.b.c", "/1/2.html?param=1")
    assertThat(e.value, is("a.b.c/1/2.html?param=1"))
    assertThat(e.hexHash.length, is(64))
  }

  @Test
  def testExpressionsOne = {
    val expressions = new ExpressionGenerator("http://a.b.c/1/2.html?param=1").expressions
    assertThat(expressions.size, is(8))
    assertTrue(expressions.contains(Expression("a.b.c", "/1/2.html?param=1")))
    assertTrue(expressions.contains(Expression("a.b.c", "/1/2.html")))
    assertTrue(expressions.contains(Expression("a.b.c", "/1/")))
    assertTrue(expressions.contains(Expression("a.b.c", "/")))
    assertTrue(expressions.contains(Expression("b.c", "/1/2.html?param=1")))
    assertTrue(expressions.contains(Expression("b.c", "/1/2.html")))
    assertTrue(expressions.contains(Expression("b.c", "/1/")))
    assertTrue(expressions.contains(Expression("b.c", "/")))
  }

  @Test
  def testExpressionsTwo = {
    val e = new ExpressionGenerator("http://12.0x12.01234/a/b/cde/f?g=foo&h=bar#quux").expressions
    assertThat(e.size, is(6))
    assertTrue(e.contains(Expression("12.18.2.156", "/a/b/cde/f?g=foo&h=bar")))
    assertTrue(e.contains(Expression("12.18.2.156", "/a/b/cde/f")))
    assertTrue(e.contains(Expression("12.18.2.156", "/a/b/cde/")))
    assertTrue(e.contains(Expression("12.18.2.156", "/a/b/")))
    assertTrue(e.contains(Expression("12.18.2.156", "/a/")))
    assertTrue(e.contains(Expression("12.18.2.156", "/")))
  }

  @Test
  def testExpressionsThree = {
    val e = new ExpressionGenerator("http://www.google.com/a/b/cde/f?g=foo&h=bar#quux").expressions
    assertThat(e.size, is(12))

    assertTrue(e.contains(Expression("www.google.com", "/a/b/cde/f?g=foo&h=bar")))
    assertTrue(e.contains(Expression("www.google.com", "/a/b/cde/f")))
    assertTrue(e.contains(Expression("www.google.com", "/a/b/cde/")))
    assertTrue(e.contains(Expression("www.google.com", "/a/b/")))
    assertTrue(e.contains(Expression("www.google.com", "/a/")))
    assertTrue(e.contains(Expression("www.google.com", "/")))

    assertTrue(e.contains(Expression("google.com", "/a/b/cde/f?g=foo&h=bar")))
    assertTrue(e.contains(Expression("google.com", "/a/b/cde/f")))
    assertTrue(e.contains(Expression("google.com", "/a/b/cde/")))
    assertTrue(e.contains(Expression("google.com", "/a/b/")))
    assertTrue(e.contains(Expression("google.com", "/a/")))
    assertTrue(e.contains(Expression("google.com", "/")))
  }

  @Test
  def testExpressionsFour = {
    val e = new ExpressionGenerator("http://a.b.c.d.e.f.g/h/i/j/k/l/m/n/o?p=foo&q=bar#quux").expressions
    assertThat(e.size, is(30))

    assertTrue(e.contains(Expression("a.b.c.d.e.f.g", "/h/i/j/k/l/m/n/o?p=foo&q=bar")))
    assertTrue(e.contains(Expression("a.b.c.d.e.f.g", "/h/i/j/k/l/m/n/o")))
    assertTrue(e.contains(Expression("a.b.c.d.e.f.g", "/h/i/j/")))
    assertTrue(e.contains(Expression("a.b.c.d.e.f.g", "/h/i/")))
    assertTrue(e.contains(Expression("a.b.c.d.e.f.g", "/h/")))
    assertTrue(e.contains(Expression("a.b.c.d.e.f.g", "/")))

    assertTrue(e.contains(Expression("c.d.e.f.g", "/h/i/j/k/l/m/n/o?p=foo&q=bar")))
    assertTrue(e.contains(Expression("c.d.e.f.g", "/h/i/j/k/l/m/n/o")))
    assertTrue(e.contains(Expression("c.d.e.f.g", "/h/i/j/")))
    assertTrue(e.contains(Expression("c.d.e.f.g", "/h/i/")))
    assertTrue(e.contains(Expression("c.d.e.f.g", "/h/")))
    assertTrue(e.contains(Expression("c.d.e.f.g", "/")))

    assertTrue(e.contains(Expression("d.e.f.g", "/h/i/j/k/l/m/n/o?p=foo&q=bar")))
    assertTrue(e.contains(Expression("d.e.f.g", "/h/i/j/k/l/m/n/o")))
    assertTrue(e.contains(Expression("d.e.f.g", "/h/i/j/")))
    assertTrue(e.contains(Expression("d.e.f.g", "/h/i/")))
    assertTrue(e.contains(Expression("d.e.f.g", "/h/")))
    assertTrue(e.contains(Expression("d.e.f.g", "/")))

    assertTrue(e.contains(Expression("e.f.g", "/h/i/j/k/l/m/n/o?p=foo&q=bar")))
    assertTrue(e.contains(Expression("e.f.g", "/h/i/j/k/l/m/n/o")))
    assertTrue(e.contains(Expression("e.f.g", "/h/i/j/")))
    assertTrue(e.contains(Expression("e.f.g", "/h/i/")))
    assertTrue(e.contains(Expression("e.f.g", "/h/")))
    assertTrue(e.contains(Expression("e.f.g", "/")))

    assertTrue(e.contains(Expression("f.g", "/h/i/j/k/l/m/n/o?p=foo&q=bar")))
    assertTrue(e.contains(Expression("f.g", "/h/i/j/k/l/m/n/o")))
    assertTrue(e.contains(Expression("f.g", "/h/i/j/")))
    assertTrue(e.contains(Expression("f.g", "/h/i/")))
    assertTrue(e.contains(Expression("f.g", "/h/")))
    assertTrue(e.contains(Expression("f.g", "/")))
  }

  @Test
  def testExpressionsFive = {
    val e = new ExpressionGenerator("http://www.phisher.co.uk/a/b").expressions
    assertThat(e.size, is(9))

    assertTrue(e.contains(Expression("www.phisher.co.uk", "/a/b")))
    assertTrue(e.contains(Expression("www.phisher.co.uk", "/a/")))
    assertTrue(e.contains(Expression("www.phisher.co.uk", "/")))

    assertTrue(e.contains(Expression("phisher.co.uk", "/a/b")))
    assertTrue(e.contains(Expression("phisher.co.uk", "/a/")))
    assertTrue(e.contains(Expression("phisher.co.uk", "/")))

    assertTrue(e.contains(Expression("co.uk", "/a/b")))
    assertTrue(e.contains(Expression("co.uk", "/a/")))
    assertTrue(e.contains(Expression("co.uk", "/")))
  }

  @Test
  def testExpressionsSix = {
    val e = new ExpressionGenerator("http://a.b/?").expressions
    assertThat(e.size, is(1))
    assertTrue(e.contains(Expression("a.b", "/")))
  }

  @Test
  def testExpressionsSeven = {
    val e = new ExpressionGenerator("http://1.2.3.4/a/b").expressions
    assertThat(e.size, is(3))
    assertTrue(e.contains(Expression("1.2.3.4", "/a/b")))
    assertTrue(e.contains(Expression("1.2.3.4", "/a/")))
    assertTrue(e.contains(Expression("1.2.3.4", "/")))
  }

  @Test
  def testExpressionsEight = {
    val e = new ExpressionGenerator("foo.com").expressions
    assertThat(e.size, is(1))
    assertTrue(e.contains(Expression("foo.com", "/")))
  }
}
