"""Fixed decision-support text for the synthetic demonstration only."""

DEVICE_CONTEXT = {
    "DEMO-NLA": {
        "condition": "Remote Desktop is configured so that Network Level Authentication is not required.",
        "meaning": "A remote connection can reach the Remote Desktop logon prompt before network-level authentication has been completed.",
        "decision": "Prioritise approval to enable Network Level Authentication after confirming that authorised administrators use supported Remote Desktop clients.",
        "approve_outcome": "Remote Desktop connections must authenticate earlier in the connection process. Older or unmanaged clients that do not support Network Level Authentication may need to be updated before they can connect.",
        "defer_outcome": "The exposed Remote Desktop logon prompt remains available to unauthenticated network connections, so the Critical risk remains open.",
    },
    "DEMO-LOCKOUT": {
        "condition": "The account lockout threshold is 0 invalid attempts, so the server does not lock an account after repeated failed sign-in attempts.",
        "meaning": "Password guessing can continue without the account-lockout safeguard slowing repeated attempts.",
        "decision": "Plan a change to the demonstration target of 10 invalid attempts and make sure the administrator account-unlock process is understood.",
        "approve_outcome": "Repeated incorrect passwords are limited by the lockout policy, but legitimate users who repeatedly mistype a password may require support to unlock their account.",
        "defer_outcome": "Repeated password attempts remain unrestricted, which keeps the High risk open.",
    },
    "DEMO-PASSWORD": {
        "condition": "The minimum password length is 8 characters instead of the demonstration target of 14 characters.",
        "meaning": "Shorter passwords generally provide less resistance against password-guessing and cracking attempts.",
        "decision": "Schedule a move to a 14-character minimum and notify affected users before they next change their password.",
        "approve_outcome": "New and changed passwords must meet the stronger length requirement; users may need guidance during the transition.",
        "defer_outcome": "The weaker password-length policy remains in effect, leaving the Moderate risk open.",
    },
}
