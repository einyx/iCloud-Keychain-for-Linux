"""Apple authentication constants."""

XCODE_VERSION = "27.0 (27A5218g)"

GSA_ENDPOINT = "https://gsa.apple.com/grandslam/GsService2"

# The platform every client-info string claims.
#
# Since 2026-10-12 Apple answers GrandSlam's "init" with ec=-80045 unless the
# claimed client matches the platform that generated the anisette data.
# Third-party anisette servers (omnisette, anisette-v3) mint their data with
# the Windows ADI libraries, so the sign-in endpoints must claim Windows
# rather than a Mac. See Dadoum/anisette-v3-server#61.
#
# One constant, so the GrandSlam, loginDelegates and escrow identities cannot
# drift apart. The volatile per-request machine data (X-Apple-I-MD*) still
# comes from the anisette server.
WINDOWS_PLATFORM = "<PC> <Windows;6.2(0,0);9200>"

# The Mac identity. Apple still expects it for get_account_settings and for
# the CloudKit keychain endpoints.
MAC_PLATFORM = "<MacBookPro18,3> <macOS;13.4.1;22F8>"

# AuthKit device description used by GrandSlam and its 2FA endpoints.
GSA_CLIENT_INFO = f"{WINDOWS_PLATFORM} <com.apple.AuthKit/1 (com.apple.akd/1.0)>"

# loginDelegates takes the PET that GsService2 issued to the Windows identity
# and rejects it when it arrives under the Mac one.
LOGIN_DELEGATES_CLIENT_INFO = f"{WINDOWS_PLATFORM} <com.apple.AOSKit/282 (com.apple.accountsd/113)>"

# get_account_settings is asked under the identity the token was minted with
# (Windows), and, for a token saved by an earlier version that minted it as a
# Mac, once more as a Mac. Apple does not document which of the two it
# honours, so neither is assumed.
ICLOUD_CLIENT_INFO = f"{MAC_PLATFORM} <com.apple.AOSKit/282 (com.apple.accountsd/113)>"
ACCOUNT_SETTINGS_CLIENT_INFOS = (
    ("Windows", LOGIN_DELEGATES_CLIENT_INFO),
    ("Mac", ICLOUD_CLIENT_INFO),
)

# escrowproxy wants the sbd UA plus a fixed X-Mme-Client-Info that overwrites
# the one the anisette server supplied.
ESCROW_CLIENT_INFO = f"{WINDOWS_PLATFORM} <com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>"
