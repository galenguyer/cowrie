from __future__ import annotations

from functools import lru_cache
import geoip2.database

from twisted.python import log

import cowrie.core.output
from cowrie.core.config import CowrieConfig


class Output(cowrie.core.output.Output):
    """
    Output plugin used for GeoIP lookup
    """

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
                geoip=result
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
                geoip=result
            )

        if entry["eventid"] == "cowrie.session.connect":
            d = self.geoip(entry["src_ip"])
            if d is not None:
                processConnect(d)
        elif entry["eventid"] == "cowrie.direct-tcpip.request":
            d = self.geoip(entry["dst_ip"])
            if d is not None:
                processForward(d)

    @lru_cache(maxsize=1000)
    def geoip(self, addr):
        """
        Perform a GeoIP lookup on an IP

        Arguments:
            addr -- IPv4 Address
        """
        city_result = self.city_db.city(ip_address=addr)
        final_result = {
            "country": {
                "name": city_result.country.name,
                "iso_code": city_result.country.iso_code
            },
            "location": {
                "latitude": city_result.location.latitude,
                "longitude": city_result.location.longitude,
            }
        }
        if city_result.subdivisions.most_specific.name:
            final_result["region"] = {
                "name": city_result.subdivisions.most_specific.name,
                "iso_code": city_result.subdivisions.most_specific.iso_code
            }
        if city_result.city.name:
            final_result["city"] = city_result.city.name

        return final_result
