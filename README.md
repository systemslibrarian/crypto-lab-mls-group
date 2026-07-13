# crypto-lab-mls-group

## What It Is

This project is a browser-first demonstration of Messaging Layer Security (MLS) and TreeKEM from RFC 9420. It targets end-to-end encrypted group messaging where membership changes are frequent and asynchronous delivery is required. The protocol model focuses on large groups where pairwise approaches become expensive. Security goals include forward secrecy and post-compromise security across epochs. All core protocol flows are presented as in-browser, inspectable state transitions.

## When to Use It

- Use it for team chat systems with larger memberships where updates must scale beyond pairwise session fanout.
- Use it for enterprise or community messaging with frequent add, remove, and update operations.
- Use it when asynchronous group delivery is needed and members may be offline during commits.
- Use it when Double Ratchet pairwise meshes become operationally heavy in large channels.
- Do not use MLS for strictly 1:1 conversations where Double Ratchet is lighter and simpler.
- Do not use MLS without a delivery service capable of reliable asynchronous fan-out.
- Do NOT treat this as production code — it is a teaching demo that visualizes the MLS/TreeKEM flow, not a hardened messaging stack.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-mls-group](https://systemslibrarian.github.io/crypto-lab-mls-group/)**

In the live demo, members have names (Alice, Bob, Charlie, …) mapped to their leaf indices, so the ratchet tree stays readable as you add and remove people. Every action is narrated in plain English ("what just happened") alongside the full protocol transcript, and a status banner always shows the current epoch and membership. **Progressive disclosure:** on first load you meet just the tree, the member controls, and the narration — the proof and internals panels stay behind labeled teasers and unlock as the guided tour reaches each concept (or all at once via **Show all panels**). New here? Click **Start guided tour** for a step-by-step walk through the whole group lifecycle. You can:

- Take the **guided tour**: add → send → update → converge → remove → locked-out → heal, each step running real commits and revealing the panel it explains.
- Add/remove members and watch the ratchet tree re-key, with the committer's direct path animating up the tree, small "sealed packet" icons flying to each copath leaf (the encrypt-to-copath step), and the epoch number rolling over.
- **Click any tree node to inspect it**: a member leaf highlights exactly the keys that person can derive (their direct path) and dims the subtrees they are blind to; a parent node shows which members share it ("Derivable by: Alice, Bob") and its HPKE public key.
- See the **TreeKEM Convergence** proof: every member independently derives the *same* root secret (the committer by ratcheting, the rest by HPKE-decrypting one path secret) — and the demo shows that shared secret **is** the live epoch's `commit_secret`, matching the Key Schedule panel's `commit_secret` chip byte-for-byte.
- Send application messages encrypted with real per-message AES-128-GCM keys from each sender's ratchet.
- Read the key schedule as a derivation diagram (init_secret + commit_secret → joiner → epoch → per-epoch secrets) with live byte values, the two secrets this demo actually uses shown up front and the other seven grouped (with one-word purposes) behind a disclosure.
- Step through a **Forward Secrecy** walkthrough: capture a message key, advance the epoch, and see the same derivation produce a different key — the old one is gone.
- Step through a **Post-Compromise Security** walkthrough: mark a member compromised, then have them commit an Update to lock the attacker out.
- Watch **Access Control** in action: the group sends a real message and a removed member fails to decrypt it while a current member succeeds.
- Run one-click scenario presets (add, remove, PCS recovery, churn drill), each performing real cryptographic commits.

## What Can Go Wrong

- Untrusted delivery service: MLS relies on an external delivery service to order and fan out handshake messages; if it drops, reorders, or withholds commits, members can desynchronize epochs and fail to converge on the shared group secret.
- Unauthenticated KeyPackages: adding a member from a forged or stale KeyPackage can let an attacker join or be impersonated — KeyPackages must be signature-verified and checked for freshness.
- Missed commits and state loss: a member that fails to process a commit cannot derive the new epoch secret and is locked out until it replays the commit/welcome chain in order.
- Post-compromise security is not automatic: a leaked leaf key keeps decrypting group traffic until the affected member performs an Update commit, so healing depends on members actually rotating.
- Metadata exposure: MLS protects message content, but the delivery service still observes group membership, size, and message timing.

## Real-World Usage

- RFC 9420: MLS is the IETF standard for scalable end-to-end encrypted group messaging, defining TreeKEM, the epoch key schedule, and the handshake message formats.
- IETF MIMI working group: MLS is the basis for the More Instant Messaging Interoperability effort aimed at cross-provider encrypted messaging.
- OpenMLS: an open-source Rust implementation of RFC 9420 used in research and product integrations.
- mlspp: Cisco's C++ MLS implementation, developed alongside the standard and used in conferencing/messaging work.
- Messaging platforms: the protocol was designed with large-group E2EE deployment in mind and has been adopted/evaluated by messaging vendors moving beyond pairwise Double Ratchet.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-mls-group
cd crypto-lab-mls-group
npm install
npm run dev
```

## Related Demos

- [crypto-lab-ratchet-wire](https://systemslibrarian.github.io/crypto-lab-ratchet-wire/) — the pairwise Double Ratchet that MLS scales past for groups.
- [crypto-lab-x3dh-wire](https://systemslibrarian.github.io/crypto-lab-x3dh-wire/) — X3DH asynchronous key agreement from the Signal stack.
- [crypto-lab-noise-pipe](https://systemslibrarian.github.io/crypto-lab-noise-pipe/) — Noise handshake patterns for authenticated secure channels.
- [crypto-lab-hybrid-wire](https://systemslibrarian.github.io/crypto-lab-hybrid-wire/) — hybrid X25519 + ML-KEM key exchange for transport.
- [crypto-lab-kerberos](https://systemslibrarian.github.io/crypto-lab-kerberos/) — a classic ticket-based key distribution protocol.

## Testing

Run the test suite (TreeKEM convergence, tree arithmetic, key schedule, forward secrecy, and removed-member lockout) with:

```bash
npm test
```

---

*One of 120+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
