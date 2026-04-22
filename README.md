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

In the live demo, you can add and remove members and observe ratchet tree changes immediately. You can run updates across epochs, inspect transcript events, and send application messages. You can also inspect derived key-schedule outputs and compare how epoch transitions affect sender ratchets.

## 4. How to Run Locally
	git clone https://github.com/systemslibrarian/crypto-lab-mls-group
	cd crypto-lab-mls-group
	npm install
	npm run dev

## 5. Part of the Crypto-Lab Suite
> One of 100+ live browser demos at
> [systemslibrarian.github.io/crypto-lab](https://systemslibrarian.github.io/crypto-lab/)
> — spanning Atbash (600 BCE) through NIST FIPS 203/204/205 (2024).

---

*"Whether you eat or drink, or whatever you do, do all to the glory of God." — 1 Corinthians 10:31*