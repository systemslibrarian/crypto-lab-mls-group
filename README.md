# crypto-lab-mls-group

## 1. What It Is
This project is a browser-first demonstration of Messaging Layer Security (MLS) and TreeKEM from RFC 9420. It targets end-to-end encrypted group messaging where membership changes are frequent and asynchronous delivery is required. The protocol model focuses on large groups where pairwise approaches become expensive. Security goals include forward secrecy and post-compromise security across epochs. All core protocol flows are presented as in-browser, inspectable state transitions.

## 2. When to Use It
- Use it for team chat systems with larger memberships where updates must scale beyond pairwise session fanout.
- Use it for enterprise or community messaging with frequent add, remove, and update operations.
- Use it when asynchronous group delivery is needed and members may be offline during commits.
- Use it when Double Ratchet pairwise meshes become operationally heavy in large channels.
- Do not use MLS for strictly 1:1 conversations where Double Ratchet is lighter and simpler.
- Do not use MLS without a delivery service capable of reliable asynchronous fan-out.

## 3. Live Demo
https://systemslibrarian.github.io/crypto-lab-mls-group/

In the live demo, members have names (Alice, Bob, Charlie, …) mapped to their leaf indices, so the ratchet tree stays readable as you add and remove people. Every action is narrated in plain English ("what just happened") alongside the full protocol transcript, and a status banner always shows the current epoch and membership. New here? Click **Start guided tour** for a step-by-step walk through the whole group lifecycle. You can:

- Take the **guided tour**: add → send → update → converge → remove → locked-out → heal, each step running real commits.
- Add/remove members and watch the ratchet tree re-key, with the committer's direct path animating up the tree and the epoch number rolling over.
- See the **TreeKEM Convergence** proof: every member independently derives the *same* root secret (the committer by ratcheting, the rest by HPKE-decrypting one path secret).
- Send application messages encrypted with real per-message AES-128-GCM keys from each sender's ratchet.
- Read the key schedule as a derivation diagram (init_secret + commit_secret → joiner → epoch → leaf secrets) with live byte values.
- Step through a **Forward Secrecy** walkthrough: capture a message key, advance the epoch, and see the same derivation produce a different key — the old one is gone.
- Step through a **Post-Compromise Security** walkthrough: mark a member compromised, then have them commit an Update to lock the attacker out.
- Watch **Access Control** in action: the group sends a real message and a removed member fails to decrypt it while a current member succeeds.
- Run one-click scenario presets (add, remove, PCS recovery, churn drill), each performing real cryptographic commits.

## 4. How to Run Locally
	git clone https://github.com/systemslibrarian/crypto-lab-mls-group
	cd crypto-lab-mls-group
	npm install
	npm run dev

Run the test suite (TreeKEM convergence, tree arithmetic, key schedule, forward secrecy, and removed-member lockout) with:

	npm test

## 5. Part of the Crypto-Lab Suite
> One of 100+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*