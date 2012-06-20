package util

import org.slf4j._

/** Handy slf4j wrapper */
trait Logging {
    /** Values used as logger name */
    protected def loggerName = this.getClass.getName.replaceFirst("\\$.*", "")
    val logger = LoggerFactory.getLogger(loggerName)
}