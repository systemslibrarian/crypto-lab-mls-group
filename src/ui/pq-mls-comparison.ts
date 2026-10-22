import { MLS_CIPHERSUITE } from '../crypto/ciphersuite';

// Examples from RFC 9420 and draft-ietf-mls-pq-ciphersuites-06, Table 1.
// These are labels for a comparison exercise, not selectable crypto in this lab.
const OPTIONS = [
  {
    label: 'Classical RFC 9420 suite',
    suite: MLS_CIPHERSUITE.name,
    kem: 'X25519 (classical)',
    signature: 'Ed25519 (classical)',
    confidentiality: 'Classical only',
    authentication: 'Classical only',
    lesson: 'This is the suite whose key-agreement and symmetric mechanics the lab models. Its Ed25519 signature layer is omitted here.'
  },
  {
    label: 'Draft hybrid KEM + classical signature',
    suite: 'MLS_128_MLKEM768X25519_AES128GCM_SHA256_Ed25519',
    kem: 'ML-KEM-768 + X25519 (hybrid)',
    signature: 'Ed25519 (classical)',
    confidentiality: 'Designed for post-quantum confidentiality',
    authentication: 'Classical only',
    lesson: 'A quantum-resistant KEM does not make its Ed25519 authentication post-quantum. The draft calls this confidentiality protection, not full post-quantum security.'
  },
  {
    label: 'Draft hybrid KEM + post-quantum signature',
    suite: 'MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44',
    kem: 'ML-KEM-768 + X25519 (hybrid)',
    signature: 'ML-DSA-44 (post-quantum)',
    confidentiality: 'Designed for post-quantum confidentiality',
    authentication: 'Designed for post-quantum authentication',
    lesson: 'This draft suite addresses both questions by pairing its hybrid KEM with ML-DSA-44 signatures. It is a proposal, not an implemented option in this lab.'
  }
] as const;

export function renderPqMlsComparison(): HTMLElement {
  const root = document.createElement('section');
  root.className = 'panel pq-mls-panel';
  const heading = document.createElement('h2');
  heading.id = 'panel-post-quantum-mls-draft';
  heading.textContent = 'Post-Quantum MLS Draft';
  root.setAttribute('aria-labelledby', heading.id);
  root.appendChild(heading);

  const intro = document.createElement('p');
  intro.textContent = 'Compare the classical suite modeled here with two proposed suites. Choose a suite to see what its KEM and signature protect.';
  root.appendChild(intro);

  const status = document.createElement('p');
  status.className = 'muted';
  status.innerHTML = '<strong>Conceptual comparison only:</strong> the proposed suites are from an Internet-Draft dated 21 July 2026, not a final MLS standard. Selecting them does not change the live group, keys, messages, or ciphersuite. This lab omits credential signatures even for the classical suite.';
  root.appendChild(status);

  const choices = document.createElement('div');
  choices.className = 'pq-mls-choices';
  choices.setAttribute('role', 'group');
  choices.setAttribute('aria-label', 'Suite to examine');

  const result = document.createElement('div');
  result.className = 'pq-mls-result';
  result.setAttribute('aria-live', 'polite');

  const buttons: HTMLButtonElement[] = [];
  const show = (selected: number) => {
    buttons.forEach((button, index) => button.setAttribute('aria-pressed', String(index === selected)));
    const option = OPTIONS[selected];
    result.replaceChildren();

    const name = document.createElement('p');
    name.className = 'pq-mls-suite';
    const code = document.createElement('code');
    code.textContent = option.suite;
    name.appendChild(code);
    result.appendChild(name);

    const dl = document.createElement('dl');
    for (const [label, value] of [
      ['Key establishment', option.kem],
      ['Signature in the suite', option.signature],
      ['Confidentiality', option.confidentiality],
      ['Authentication', option.authentication]
    ]) {
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = value;
      dl.append(dt, dd);
    }
    result.appendChild(dl);
    const takeaway = document.createElement('p');
    takeaway.textContent = option.lesson;
    result.appendChild(takeaway);
  };

  OPTIONS.forEach((option, index) => {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = option.label;
    button.onclick = () => show(index);
    buttons.push(button);
    choices.appendChild(button);
  });
  root.append(choices, result);
  show(0);

  const sources = document.createElement('p');
  sources.className = 'muted';
  sources.innerHTML = 'Sources: <a href="https://www.rfc-editor.org/rfc/rfc9420#section-17.1" target="_blank" rel="noreferrer">RFC 9420 §17.1</a>; <a href="https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-06#section-3.1" target="_blank" rel="noreferrer">MLS PQ ciphersuites draft-06 §3.1</a> and <a href="https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-06#section-4" target="_blank" rel="noreferrer">§4 security considerations</a> (21 July 2026, work in progress).';
  root.appendChild(sources);
  return root;
}
