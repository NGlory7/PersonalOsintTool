"""
Phone Number OSINT Analyzer: Carrier, geocoding, line type, format generation, and dorking links.
"""

from dataclasses import dataclass, field
from typing import List, Optional
import urllib.parse
import phonenumbers
from phonenumbers import geocoder, carrier, timezone


@dataclass
class PhoneReport:
    raw_input: str
    is_valid: bool
    e164_format: Optional[str] = None
    international_format: Optional[str] = None
    national_format: Optional[str] = None
    country_code: Optional[int] = None
    country_name: Optional[str] = None
    location: Optional[str] = None
    carrier_name: Optional[str] = None
    line_type: Optional[str] = None
    timezones: List[str] = field(default_factory=list)
    dork_links: List[dict] = field(default_factory=list)
    chat_links: List[dict] = field(default_factory=list)


class PhoneScanner:
    LINE_TYPES = {
        phonenumbers.PhoneNumberType.FIXED_LINE: "Fixed Line (Sabit Hat)",
        phonenumbers.PhoneNumberType.MOBILE: "Mobile (Mobil Hat)",
        phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        phonenumbers.PhoneNumberType.TOLL_FREE: "Toll Free (Ücretsiz Hat)",
        phonenumbers.PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        phonenumbers.PhoneNumberType.SHARED_COST: "Shared Cost",
        phonenumbers.PhoneNumberType.VOIP: "VOIP (İnternet Telefonu)",
        phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        phonenumbers.PhoneNumberType.PAGER: "Pager",
        phonenumbers.PhoneNumberType.UAN: "Universal Access Number (UAN)",
        phonenumbers.PhoneNumberType.VOICEMAIL: "Voicemail",
        phonenumbers.PhoneNumberType.UNKNOWN: "Unknown (Bilinmiyor)"
    }

    def analyze(self, raw_number: str, default_region: str = "TR") -> PhoneReport:
        clean_input = raw_number.strip().replace(" ", "").replace("-", "")

        try:
            # If number doesn't start with +, use default_region (e.g. TR)
            parsed = phonenumbers.parse(raw_number, default_region)
        except phonenumbers.NumberParseException:
            return PhoneReport(raw_input=raw_number, is_valid=False)

        valid = phonenumbers.is_valid_number(parsed)
        if not valid:
            return PhoneReport(raw_input=raw_number, is_valid=False)

        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nat = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)

        country = geocoder.country_name_for_number(parsed, "tr") or geocoder.country_name_for_number(parsed, "en")
        loc = geocoder.description_for_number(parsed, "tr") or geocoder.description_for_number(parsed, "en")
        c_name = carrier.name_for_number(parsed, "tr") or carrier.name_for_number(parsed, "en")
        l_type = self.LINE_TYPES.get(phonenumbers.number_type(parsed), "Unknown")
        tz_list = list(timezone.time_zones_for_number(parsed))

        digits_only = e164.replace("+", "")

        # Generate dork and direct links
        chat_links = [
            {"name": "WhatsApp Direct", "url": f"https://wa.me/{digits_only}"},
            {"name": "Telegram", "url": f"https://t.me/+{digits_only}"},
            {"name": "Viber Direct", "url": f"viber://chat?number={digits_only}"}
        ]

        q_intl = f'"{intl}"'
        q_nat = f'"{nat}"'
        q_e164 = f'"{e164}"'

        dorks = [
            {
                "title": f'Google Exact ({q_intl})',
                "url": f'https://www.google.com/search?q={urllib.parse.quote(q_intl)}'
            },
            {
                "title": f'Google Local ({q_nat})',
                "url": f'https://www.google.com/search?q={urllib.parse.quote(q_nat)}'
            },
            {
                "title": f'Google E.164 ({q_e164})',
                "url": f'https://www.google.com/search?q={urllib.parse.quote(q_e164)}'
            },
            {
                "title": "Truecaller Lookup",
                "url": f"https://www.truecaller.com/search/{parsed.country_code}/{parsed.national_number}"
            },
            {
                "title": "Sync.me Lookup",
                "url": f"https://sync.me/search/?number={digits_only}"
            }
        ]

        return PhoneReport(
            raw_input=raw_number,
            is_valid=True,
            e164_format=e164,
            international_format=intl,
            national_format=nat,
            country_code=parsed.country_code,
            country_name=country,
            location=loc,
            carrier_name=c_name,
            line_type=l_type,
            timezones=tz_list,
            dork_links=dorks,
            chat_links=chat_links
        )
