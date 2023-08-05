from __future__ import annotations

from functools import lru_cache
import geoip2.database

from twisted.internet import defer
from twisted.names import client, error
from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    Output plugin used for GeoIP lookup
    """

    timeout: list[int] = [3]

    def start(self):
        """
        Start Output Plugin
        """
        self.db_path = CowrieConfig.getint("output_geoip", "db_path", fallback="/var/lib/GeoIP")
        self.city_db = geoip2.database.Reader(f"{self.db_path}/GeoLite2-City.mmdb")

    def stop(self):
        """
        Stop Output Plugin
        """
        pass

    def write(self, entry):
        """
        Process log entry
        """

        def processConnect(result):
            """
            Create log messages for connect events
            """
            if result is None:
                return
            log.msg(
                eventid="cowrie.geoip.connect",
                session=entry["session"],
                format="geoip: GeoIP record for IP %(src_ip)s found",
                src_ip=entry["src_ip"],
                geoip={
                    "country": {
                        "name": result.country.name,
                        "iso_code": result.country.iso_code
                    }
                }
            )

        def processForward(result):
            """
            Create log messages for forward events
            """
            if result is None:
                return
            log.msg(
                eventid="cowrie.geoip.forward",
                session=entry["session"],
                format="geoip: GeoIP record for IP %(dst_ip)s found",
                dst_ip=entry["dst_ip"],
                geoip={
                    "country": {
                        "name": result.country.name,
                        "iso_code": result.country.iso_code
                    }
                }
            )

        def cbError(failure):
            log.msg("geoip: Error in GeoIP lookup")
            failure.printTraceback()

        if entry["eventid"] == "cowrie.session.connect":
            d = self.geoip(entry["src_ip"])
            if d is not None:
                d.addCallback(processConnect)
                d.addErrback(cbError)
        elif entry["eventid"] == "cowrie.direct-tcpip.request":
            d = self.geoip(entry["dst_ip"])
            if d is not None:
                d.addCallback(processForward)
                d.addErrback(cbError)

    @lru_cache(maxsize=1000)
    def geoip(self, addr):
        """
        Perform a GeoIP lookup on an IP

        Arguments:
            addr -- IPv4 Address
        """
        return self.city_db.city(ip_address=addr)
