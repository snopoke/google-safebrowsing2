package util

import java.sql._
import javax.sql.DataSource
import scala.collection.mutable.ArrayBuffer
import JdbcImplicits._
import org.joda.time.Instant
import org.joda.time.ReadableInstant

/**
 * @see https://bitbucket.org/stepancheg/scala-misc/
 */

trait JdbcImplicits {
    implicit def jdbcTemplate(ds: LiteDataSource) = new JdbcTemplate(ds)
    
    implicit def resultSetExtras(rs: ResultSet) = new ResultSetExtras(rs)
    
    implicit def preparedStatementExtras(ps: PreparedStatement) = new PreparedStatementExtras(ps)
}

object JdbcImplicits extends JdbcImplicits



/**
 * Slightly different variant of <code>javax.sql.DataSource</code>
 * 
 * @see http://jira.springframework.org/browse/SPR-5532
 */
trait LiteDataSource {
    /** Obtain new connection */
    def openConnection(): Connection
    /**
      * Release connection obtained by this data source,
      * just delegate to <code>Connection.close()</code> in this impl
      */
    def closeConnection(c: Connection) = c.close()
    /** Close data source, do nothing by default */
    def close() = ()
}

/**
 * Factories to create data source
 */
object LiteDataSource extends Logging {
    /** Create from function, returning connection */
    def apply(f: () => Connection): LiteDataSource = new LiteDataSource {
        override def openConnection() = f()
    }
    
    /** Wrap <code>javax.sql.DataSource</code> */
    def apply(ds: DataSource): LiteDataSource = apply(() => ds.getConnection())
    
    /** Obtain from <code>DriverManager</code> using specified URL, login and password */
    def driverManager(url: String, user: String, password: String) =
        new DriverManagerLiteDataSource(url, Some((user, password)))
    
    /** Obtain from <code>DriverManager</code> by URL */
    def driverManager(url: String) =
        new DriverManagerLiteDataSource(url, None)
    
    /** Data source that always feeds same connection. Connection is never closed by data source */
    def singleConnection(c: Connection) = new SingleConnectionLiteDataSource(c)
    
}

class DriverManagerLiteDataSource(url: String, userPassword: Option[(String, String)]) extends LiteDataSource {
    require(url != null && url.length > 0, "url must be not empty")
    override def openConnection() =
        userPassword match {
            case Some((user, password)) =>
                java.sql.DriverManager.getConnection(url, user, password)
            case None =>
                java.sql.DriverManager.getConnection(url)
        }
}
    
/**
 * Simple data source that shares same connection
 */
class SingleConnectionLiteDataSource(c: Connection) extends LiteDataSource {
    override def openConnection() = c
    override def closeConnection(c: Connection) = ()
}

/**
 * Data source that obtains connection from the given data souce and caches it.
 */
class CacheConnectionLiteDataSource(ds: LiteDataSource) extends LiteDataSource {
    private var cached: Option[Connection] = None
    
    override def openConnection() = synchronized {
        cached match {
            case Some(c) => c
            case None =>
                val c = ds.openConnection()
                cached = Some(c)
                c
        }
    }
    
    override def closeConnection(c: Connection) = ()
    
    /** Release cached connection */
    override def close() = synchronized {
        cached match {
            case Some(c) =>
                ds.closeConnection(c)
                cached = None
            case None =>
        }
    }
}

/** JdbcTemplate implementation */
trait JdbcOperations extends Logging {
    val ds: LiteDataSource
    import ds._
    
    // copy from scalax.resource
    def foreach(f: Connection => Unit): Unit = acquireFor(f)
    def flatMap[B](f: Connection => B): B = acquireFor(f)
    def map[B](f: Connection => B): B = acquireFor(f)

    /** Acquires the resource for the duration of the supplied function. */
    private def acquireFor[B](f: Connection => B): B = {
        val c = openConnection()
        try {
            f(c)
        } finally {
            closeConnectionQuietly(c)
        }
    }
    
    trait Query {
        def prepareStatement(conn: Connection): PreparedStatement
        
        def execute[T](rse: ResultSet => T) =
            JdbcOperations.this.execute { conn =>
                val ps = prepareStatement(conn)
                try {
                    val rs = ps.executeQuery()
                    rse(rs)
                } finally {
                    close(ps)
                }
            }
        
        def seq[T](rm: ResultSet => T): Seq[T] =
            execute { _.read(rm) }
        
        def seq[T]()(implicit mf: scala.reflect.Manifest[T]): Seq[T] =
            execute { _.read[T]() }
       
        def seq[T](t: Class[T]): Seq[T] =
            execute { _.read(t) }
       
        def single[T](rm: ResultSet => T): T =
            execute { _.readSingle(rm) }
       
        def single[T]()(implicit mf: scala.reflect.Manifest[T]): T =
            execute { _.readSingle[T]() }
        
        def single[T](t: Class[T]): T =
            execute { _.readSingle(t) }
       
        def option[T](rm: ResultSet => T): Option[T] =
            execute { _.readOption(rm) }
        
        def option[T]()(implicit mf: scala.reflect.Manifest[T]): Option[T] =
            execute { _.readOption[T]() }
       
        def option[T](t: Class[T]): Option[T] =
            execute { _.readOption(t) }
       
        def long() = execute { _.readLong() }
        def longs() = execute { _.readLongs() }
        
        def int() = execute { _.readInt() }
        def ints() = execute { _.readInts() }
        
        def string() = execute { _.readString() }
        def strings() = execute { _.readStrings() }
    }
    
    /** Close quietly */
    private def close(o: { def close() }) {
        if (o != null)
            try {
                o.close()
            } catch {
                case e => logger.warn("failed to close something: " + e, e)
            }
    }
    
    def closeConnectionQuietly(c: Connection) =
        try {
            closeConnection(c)
        } catch {
            case e => logger.warn("failed to close connection: " + e, e)
        }
    
    def execute[T](ccb: Connection => T): T = {
        val conn = openConnection()
        try {
            ccb(conn)
        } finally {
            closeConnectionQuietly(conn)
        }
    }
    
    def execute[T](psc: Connection => PreparedStatement, f: PreparedStatement => T): T = {
        execute { conn =>
            val ps = psc(conn)
            try {
                f(ps)
            } finally {
                close(ps)
            }
        }
    }
    
    def executePsc[T](q: String, f: PreparedStatement => T): T = execute(_.prepareStatement(q), f)
    
    def execute(q: String, params: Any*): Unit = executePsc(q, { ps: PreparedStatement =>
        ps.setParams(params)
        ps.execute()
    })

    /**
     * Batch update
     */
    def executeBatch(q: String, argSeq: Seq[Seq[Any]]): Unit = execute(q, { ps: PreparedStatement =>
        for (params <- argSeq) {
            ps.setParams(params)
            ps.addBatch()
        }
        ps.executeBatch()
    })
    
    def update(q: String, params: Any*): Int = executePsc(q, { ps: PreparedStatement =>
        ps.setParams(params)
        ps.executeUpdate()
    })
    
    def updateRow(q: String, params: Any*): Unit = {
        val count = update(q, params: _*)
        if (count != 1)
            throw new Exception("expected to update one row, updated " + count)
    }
    
    def updateRowGetGeneratedKey(q: String, params: Any*): Long =
        execute(_.prepareStatement(q, Statement.RETURN_GENERATED_KEYS), { ps: PreparedStatement =>
            ps.setParams(params)
            val count = ps.executeUpdate()
            if (count != 1)
                throw new Exception("expected to update one row, updated " + count)
            ps.getGeneratedKeys().readLong()
        })
    
    class ParamsQuery(q: String, params: Any*) extends Query {
        override def prepareStatement(conn: Connection) = {
            val ps = conn.prepareStatement(q)
            ps.setParams(params)
            ps
        }
    }
    
    /** Specify SQL and params for query, result object can be used to actually query the data */
    def query(q: String) = new ParamsQuery(q, Nil: _*)
    
    /** Specify SQL and params for query, result object can be used to actually query the data */
    def query(q: String, params: Any*) = new ParamsQuery(q, params: _*)
    
    /** Fetch meta data in the safe way */
    def metaData[T](cb: DatabaseMetaData => T) = acquireFor { c: Connection => cb(c.getMetaData) }
}

/** Canonical JdbcTemplate */
class JdbcTemplate(override val ds: LiteDataSource) extends JdbcOperations {
    
    def this(ds: () => Connection) = this(LiteDataSource(ds))
    def this(ds: DataSource) = this(LiteDataSource(ds))

}

class ResultSetExtras(rs: ResultSet) {
    import rs._
    
    private def mapNull[T <: AnyRef](value: T) = value match {
        case null => None
        case value => Some(value)
    }
    private def mapWasNull[T](value: T) =
        if (wasNull) None
        else Some(value)
    
    def getStringOption(column: Int) = mapNull(rs.getString(column))
    def getStringOption(column: String) = mapNull(rs.getString(column))
    
    def getIntOption(column: Int) = mapWasNull(rs.getInt(column))
    def getIntOption(column: String) = mapWasNull(rs.getInt(column))
    
    def getInstant(column: Int) = new Instant(rs.getTimestamp(column).getTime)
    def getInstant(column: String) = new Instant(rs.getTimestamp(column).getTime)
    
    def read[T](rm: ResultSet => T): Seq[T] = {
        val r = new ArrayBuffer[T]
        while (rs.next()) {
            r += rm(rs)
        }
        r
    }
    
    private def checkSingleColumn() =
        if (getMetaData.getColumnCount != 1)
            throw new Exception("expecting single column result set") // XXX
    
    def readSingleColumn[T](rm: ResultSet => T): Seq[T] = {
        checkSingleColumn()
        read(rm)
    }
    
    def readSingle[T](rm: ResultSet => T): T = {
        if (!next())
            throw new Exception("result set is empty")
        val r = rm(rs)
        if (next())
            throw new Exception("result set contains more then one row")
        r
    }
    
    def readSingleCell[T](rm: ResultSet => T): T = {
        checkSingleColumn()
        readSingle(rm)
    }
    
    def readOption[T](rm: ResultSet => T): Option[T] = {
        if (!next()) {
            None
        } else {
            val r = rm(rs)
            if (next())
                throw new Exception("result set contains more then one row")
            Some(r)
        }
    }
    
    def readOptionCell[T](rm: ResultSet => T): Option[T] = {
        checkSingleColumn()
        readOption(rm)
    }
    
    def firstColumnRowMapper[T]()(implicit mf: scala.reflect.Manifest[T]): ResultSet => T =
        firstColumnRowMapper(mf.erasure.asInstanceOf[Class[T]])
    
    def firstColumnRowMapper[T](t: Class[T]): ResultSet => T = {
        if (t == classOf[String])
            _.getString(1).asInstanceOf[T]
        else if (t == classOf[Int])
            _.getInt(1).asInstanceOf[T]
        else if (t == classOf[Long])
            _.getLong(1).asInstanceOf[T]
        else if (t == classOf[Short])
            _.getShort(1).asInstanceOf[T]
        else if (t == classOf[Byte])
            _.getByte(1).asInstanceOf[T]
        else if (t == classOf[Double])
            _.getDouble(1).asInstanceOf[T]
        else if (t == classOf[Float])
            _.getFloat(1).asInstanceOf[T]
        else
            throw new IllegalArgumentException("don't know how to map to " + t)
    }
    
    def read[T]()(implicit mf: scala.reflect.Manifest[T]): Seq[T] =
        readSingleColumn(firstColumnRowMapper[T]())
   
    def read[T](t: Class[T]): Seq[T] =
        readSingleColumn(firstColumnRowMapper(t))
   
    def readSingle[T]()(implicit mf: scala.reflect.Manifest[T]): T =
        readSingleCell(firstColumnRowMapper[T]())
    
    def readSingle[T](t: Class[T]): T =
        readSingleCell(firstColumnRowMapper(t))
    
    def readOption[T]()(implicit mf: scala.reflect.Manifest[T]): Option[T] =
        readOptionCell(firstColumnRowMapper[T]())
    
    def readOption[T](t: Class[T]): Option[T] =
        readOptionCell(firstColumnRowMapper(t))
    
    def readInt() = readSingle[Int]()
    def readInts() = read[Int]()
    
    def readLong() = readSingle[Long]()
    def readLongs() = read[Long]()
    
    def readString() = readSingle[String]()
    def readStrings() = read[String]()
   
    def readValues() =
        read {
            rs =>
                (1 to rs.getMetaData.getColumnCount)
                    .map(i => (rs.getMetaData.getColumnName(i), rs.getObject(i)))
                    .toList
        }
}

class PreparedStatementExtras(ps: PreparedStatement) {
    import ps._
    
    /** Set joda-time Instant */
    def setInstant(n: Int, i: ReadableInstant) =
        setTimestamp(n, new java.sql.Timestamp(i.getMillis))

    /** Better then setObject */
    def setAny(n: Int, value: Any) = value match {
        case i: Int => setInt(n, i)
        case l: Long => setLong(n, l)
        case f: Float => setFloat(n, f)
        case d: Double => setDouble(n, d)
        case b: Boolean => setBoolean(n, b)
        case s: String => setString(n, s)
        case dt: Date =>  setTimestamp(n, new java.sql.Timestamp(dt.getTime))
        
        case i: ReadableInstant => setInstant(n, i)
        
        case x => ps.setObject(n, x)
    }
    
    def setParams(params: Seq[Any]) = {
        for ((arg, index) <- params.toList.zipWithIndex) {
            setAny(index + 1, arg)
        }
    }
    
}