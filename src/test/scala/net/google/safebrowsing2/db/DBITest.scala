package net.google.safebrowsing2.db
import org.junit.Test
import org.junit.Before
import org.junit.Assert._
import org.hamcrest.CoreMatchers._
import util.JdbcTemplate
import util.LiteDataSource
import org.joda.time.DateTime
import org.joda.time.Duration
import net.google.safebrowsing2._

class DBITest {

  var jt: JdbcTemplate = null
  var dbi: DBI = null

  @Before
  def setup = {
    val ds = LiteDataSource.driverManager("jdbc:hsqldb:mem:unit-testing", "sa", "")
    jt = new JdbcTemplate(ds)
    dbi = new HSQLDB(jt, "")
    dbi.reset("list1")
    dbi.reset("list2")
  }

  @Test
  def testAddChunks_a = {
    dbi.addChunks_a(123, Seq(("hostkey", Seq("p1", "p2"))), "list1")
    val res = jt.query("SELECT * FROM " + dbi.TABLE_PREFIX + "AddChunks WHERE sList = ?", "list1").seq(rs => {
      (rs.getInt("iAddChunkNum"),
        rs.getString("sHostkey"),
        rs.getString("sPrefix"),
        rs.getString("sList"))
    })
    assertThat(res.length, is(2))
    assertThat(res(0), is((123, "hostkey", "p1", "list1")))
    assertThat(res(1), is((123, "hostkey", "p2", "list1")))
  }

  @Test
  def testAddChunks_aMultiple = {
    dbi.addChunks_a(123, Seq(("hostkey1", Seq("p1", "p2")),("hostkey2", Seq("p3")),("hostkey3", Seq(""))), "list1")
    val res = jt.query("SELECT * FROM " + dbi.TABLE_PREFIX + "AddChunks WHERE sList = ?", "list1").seq(rs => {
      (rs.getInt("iAddChunkNum"),
        rs.getString("sHostkey"),
        rs.getString("sPrefix"),
        rs.getString("sList"))
    })
    assertThat(res.length, is(4))
    assertThat(res(0), is((123, "hostkey1", "p1", "list1")))
    assertThat(res(1), is((123, "hostkey1", "p2", "list1")))
    assertThat(res(2), is((123, "hostkey2", "p3", "list1")))
    assertThat(res(3), is((123, "hostkey3", "", "list1")))
  }

  @Test
  def testAddChunks_s = {
    dbi.addChunks_s(123, Seq(("hostkey", Seq((1, "p1"), (2, "p2")))), "list1")
    val res = jt.query("SELECT * FROM " + dbi.TABLE_PREFIX + "SubChunks WHERE sList = ?", "list1").seq(rs => {
      (rs.getInt("iAddChunkNum"),
        rs.getInt("iSubChunkNum"),
        rs.getString("sHostkey"),
        rs.getString("sPrefix"),
        rs.getString("sList"))
    })
    assertThat(res.length, is(2))
    assertThat(res(0), is((1, 123, "hostkey", "p1", "list1")))
    assertThat(res(1), is((2, 123, "hostkey", "p2", "list1")))
  }

  @Test
  def testAddChunks_sMultiple = {
    dbi.addChunks_s(123, Seq(("hostkey1", Seq((1, "p1"), (2, "p2"))),("hostkey2", Seq((3, "p3"))),("hostkey3", Seq((4, "")))), "list1")
    val res = jt.query("SELECT * FROM " + dbi.TABLE_PREFIX + "SubChunks WHERE sList = ?", "list1").seq(rs => {
      (rs.getInt("iAddChunkNum"),
        rs.getInt("iSubChunkNum"),
        rs.getString("sHostkey"),
        rs.getString("sPrefix"),
        rs.getString("sList"))
    })
    assertThat(res.length, is(4))
    assertThat(res(0), is((1, 123, "hostkey1", "p1", "list1")))
    assertThat(res(1), is((2, 123, "hostkey1", "p2", "list1")))
    assertThat(res(2), is((3, 123, "hostkey2", "p3", "list1")))
    assertThat(res(3), is((4, 123, "hostkey3", "", "list1")))
  }

  @Test
  def testGetChunksForHostKeysSingleKey = {
    dbi.addChunks_a(1, Seq(("hostkey", Seq("p1", "p2"))), "list1")
    dbi.addChunks_a(2, Seq(("hostkey", Seq("p3", "p4"))), "list1")
    dbi.addChunks_s(3, Seq(("hostkey", Seq((1, "p1"), (2, "p3")))), "list1")

    val chunks = dbi.getChunksForHostKeys(Set("hostkey"))
    assertThat(chunks.length, is(2))
    assertThat(chunks(0), is(Chunk(1, "p2", "hostkey", "list1")))
    assertThat(chunks(1), is(Chunk(2, "p4", "hostkey", "list1")))
  }

  @Test
  def testGetChunksForHostKeysSingleKeyWithEmptySubPrefix = {
    dbi.addChunks_a(1, Seq(("hostkey", Seq("p1", "p2"))), "list1")
    dbi.addChunks_a(2, Seq(("hostkey", Seq("p3", "p4"))), "list1")
    dbi.addChunks_a(3, Seq(("hostkey", Seq("p5", "p6"))), "list1")
    dbi.addChunks_s(4, Seq(("hostkey", Seq((1, "p1"), (2, "p3")))), "list1")
    dbi.addChunks_s(4, Seq(("hostkey", Seq((3, "")))), "list1")

    val chunks = dbi.getChunksForHostKeys(Set("hostkey"))
    assertThat(chunks.length, is(2))
    assertThat(chunks(0), is(Chunk(1, "p2", "hostkey", "list1")))
    assertThat(chunks(1), is(Chunk(2, "p4", "hostkey", "list1")))
  }

  @Test
  def testGetChunksForHostKeysMultipleKeys = {
    dbi.addChunks_a(1, Seq(("hostkey1", Seq("p1", "p2"))), "list1")
    dbi.addChunks_a(2, Seq(("hostkey1", Seq("p3", "p4"))), "list1")
    dbi.addChunks_s(3, Seq(("hostkey1", Seq((1, "p1"), (2, "p3")))), "list1")

    dbi.addChunks_a(4, Seq(("hostkey2", Seq("p5", "p6"))), "list1")
    dbi.addChunks_a(5, Seq(("hostkey2", Seq("p7", "p8"))), "list1")
    dbi.addChunks_s(6, Seq(("hostkey2", Seq((4, ""), (5, "p8")))), "list1")

    val chunks = dbi.getChunksForHostKeys(Set("hostkey1", "hostkey2", "hostkey3"))
    assertThat(chunks.length, is(3))
    assertThat(chunks(0), is(Chunk(1, "p2", "hostkey1", "list1")))
    assertThat(chunks(1), is(Chunk(2, "p4", "hostkey1", "list1")))
    assertThat(chunks(2), is(Chunk(5, "p7", "hostkey2", "list1")))
  }

  @Test
  def testGetChunksForHostKeysMultipleKeysInOneChunk = {
    dbi.addChunks_a(1, Seq(("hostkey1", Seq("p1", "p2")), ("hostkey2", Seq("p5", "p6"))), "list1")
    dbi.addChunks_a(2, Seq(("hostkey1", Seq("p3", "p4")), ("hostkey2", Seq("p7", "p8"))), "list1")
    dbi.addChunks_s(3, Seq(("hostkey1", Seq((1, "p1"), (2, "p3"))), ("hostkey2", Seq((1, ""), (2, "p8")))), "list1")

    val chunks = dbi.getChunksForHostKeys(Set("hostkey1", "hostkey2", "hostkey3"))
    assertThat(chunks.length, is(3))
    assertThat(chunks(0), is(Chunk(1, "p2", "hostkey1", "list1")))
    assertThat(chunks(1), is(Chunk(2, "p4", "hostkey1", "list1")))
    assertThat(chunks(2), is(Chunk(2, "p7", "hostkey2", "list1")))
  }

  @Test
  def testGetAddChunksNums = {
    dbi.addChunks_a(1, Seq(("hostkey", Seq("p1", "p2"))), "list1")
    dbi.addChunks_a(2, Seq(("hostkey", Seq("p3", "p4"))), "list2")

    val nums = dbi.getAddChunksNums("list1")
    assertThat(nums.length, is(1))
    assertThat(nums(0), is(1))
  }

  @Test
  def testGetSubChunksNums = {
    dbi.addChunks_s(1, Seq(("hostkey", Seq((1, "p1"), (1, "p3")))), "list1")
    dbi.addChunks_s(2, Seq(("hostkey", Seq((2, "p2"), (2, "p4")))), "list2")

    val nums = dbi.getSubChunksNums("list1")
    assertThat(nums.length, is(1))
    assertThat(nums(0), is(1))
  }

  @Test
  def testDeleteAddChunks = {
    dbi.addChunks_a(1, Seq(("hostkey", Seq("p1", "p2"))), "list1")
    dbi.addChunks_a(2, Seq(("hostkey", Seq("p3", "p4"))), "list1")
    dbi.addChunks_a(1, Seq(("hostkey", Seq("p1", "p2"))), "list2")

    dbi.deleteAddChunks(Seq(1, 2), "list1")
    val nums = dbi.getAddChunksNums("list1")
    assertTrue(nums.isEmpty)

    val nums2 = dbi.getAddChunksNums("list2")
    assertThat(nums2.length, is(1))
  }

  @Test
  def testDeleteSubChunks = {
    dbi.addChunks_s(1, Seq(("hostkey", Seq((1, "p1"), (1, "p3")))), "list1")
    dbi.addChunks_s(2, Seq(("hostkey", Seq((1, "p2"), (1, "p4")))), "list1")
    dbi.addChunks_s(1, Seq(("hostkey", Seq((2, "p2"), (2, "p4")))), "list2")

    dbi.deleteSubChunks(Seq(1, 2), "list1")
    val nums = dbi.getSubChunksNums("list1")
    assertTrue(nums.isEmpty)

    val nums2 = dbi.getSubChunksNums("list2")
    assertThat(nums2.length, is(1))
  }

  @Test
  def testGetFullHashes = {
    dbi.addFullHashes(new DateTime().minusMinutes(46), Seq(Hash(1, "hash1", "list1")))
    dbi.addFullHashes(new DateTime(), Seq(Hash(1, "hash2", "list1")))
    dbi.addFullHashes(new DateTime(), Seq(Hash(3, "hash3", "list2")))

    val hashes = dbi.getFullHashes(1, new DateTime().minusMinutes(45), "list1")
    assertThat(hashes.length, is(1))
    assertThat(hashes(0), is("hash2"))
  }

  @Test
  def testUpdateSuccess_insert = {
    val now = new DateTime().withMillisOfSecond(0)
    dbi.updateSuccess(now, now.plusMinutes(5), "list1")

    val status = dbi.getListStatus("list1")
    assertTrue(status.isDefined)
    assertThat(status.get, is(Status(now, Some(now), now.plusMinutes(5), 0)))
  }

  @Test
  def testUpdateSuccess_update = {
    val now = new DateTime().withMillisOfSecond(0)
    dbi.updateSuccess(now.minusHours(1), now.minusHours(1).plusMinutes(5), "list1")
    dbi.updateSuccess(now, now.plusMinutes(5), "list1")

    val status = dbi.getListStatus("list1")
    assertTrue(status.isDefined)
    assertThat(status.get, is(Status(now, Some(now), now.plusMinutes(5), 0)))
  }

  @Test
  def testUpdateError_insert = {
    val now = new DateTime().withMillisOfSecond(0)
    dbi.updateError(now, "list1")

    val status = dbi.getListStatus("list1")
    assertTrue(status.isDefined)
    assertThat(status.get, is(Status(now, None, now.plusMinutes(1), 1)))
  }

  @Test
  def testUpdateError_update = {
    val now = new DateTime().withMillisOfSecond(0)
    dbi.updateSuccess(now.minusHours(1), now.minusHours(1).plusMinutes(5), "list1")
    dbi.updateError(now, "list1")

    val status = dbi.getListStatus("list1")
    assertTrue(status.isDefined)
    assertThat(status.get, is(Status(now, Some(now.minusHours(1)), now.plusMinutes(1), 1)))
  }

  @Test
  def testDeleteFullHashes = {
    dbi.addFullHashes(new DateTime(), Seq(Hash(1, "hash1", "list1")))
    dbi.addFullHashes(new DateTime(), Seq(Hash(2, "hash2", "list1")))
    dbi.addFullHashes(new DateTime(), Seq(Hash(1, "hash3", "list2")))

    dbi.deleteFullHashes(Seq(1, 2), "list1")

    var hashes = dbi.getFullHashes(1, new DateTime().minusMinutes(5), "list1")
    assertTrue(hashes.isEmpty)

    hashes = dbi.getFullHashes(2, new DateTime().minusMinutes(5), "list1")
    assertTrue(hashes.isEmpty)

    hashes = dbi.getFullHashes(1, new DateTime().minusMinutes(5), "list2")
    assertThat(hashes.length, is(1))
  }

  @Test
  def testFullHashError_insert = {
    val now = new DateTime().withMillisOfSecond(0)
    dbi.fullHashError(now, "hash1")

    val status = dbi.getFullHashError("hash1")
    assertTrue(status.isDefined)
    assertThat(status.get, is(Status(now, None, now.plusMinutes(1), 1)))
  }

  @Test
  def testFullHashError_backOff = {
    val now = new DateTime().withMillisOfSecond(0)
    dbi.fullHashError(now, "hash1")
    dbi.fullHashError(now, "hash1")

    val status = dbi.getFullHashError("hash1")
    assertTrue(status.isDefined)
    assertThat(status.get, is(Status(now, None, now.plusMinutes(30), 2)))
  }

  @Test
  def testFullHashError_noBackOff = {
    val now = new DateTime().withMillisOfSecond(0)
    dbi.fullHashError(now.minusMinutes(6), "hash1")
    dbi.fullHashError(now, "hash1")

    val status = dbi.getFullHashError("hash1")
    assertTrue(status.isDefined)
    assertThat(status.get, is(Status(now, None, now, 1)))
  }

  @Test
  def testClearFullHashErrors = {
    val expression = Expression("host","path")

    val now = new DateTime().withMillisOfSecond(0)
    dbi.fullHashError(now, expression.hexHash)

    dbi.clearFullhashErrors(Seq(expression))
    val status = dbi.getFullHashError(expression.hexHash)
    assertTrue(status.isEmpty)
  }

  @Test
  def testAddMacKey = {
    val now = new DateTime().withMillisOfSecond(0)
    dbi.addMacKey(MacKey("client", "wrapped"))

    val key = dbi.getMacKey()
    assertTrue(key.isDefined)
    assertThat(key.get, is(MacKey("client", "wrapped")))
  }
  
  @Test
  def testClearExpiredHashes = {
    dbi.addFullHashes(new DateTime().minusMinutes(46), Seq(Hash(1, "hash1", "list1")))
    dbi.addFullHashes(new DateTime(), Seq(Hash(1, "hash2", "list1")))

    dbi.clearExpiredHashes
    
    val hashes = dbi.getFullHashes(1, new DateTime().minusMinutes(100), "list1")
    assertThat(hashes.length, is(1))
    assertThat(hashes(0), is("hash2"))
  }

}
