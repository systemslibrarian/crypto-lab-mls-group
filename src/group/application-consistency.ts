export interface AppMessage { id: string; sender: string; sequence: number; kind: 'poll' | 'edit'; question?: string; choices?: string[]; field?: string; value?: string }
export interface Delivery { message: AppMessage; decrypted: boolean; authenticated: boolean }
export type Scenario = 'equivocation' | 'honest' | 'missing' | 'altered' | 'malformed';

/** Distinct checks; a shared epoch key is deliberately not an input. */
export function compareHistories(histories: Delivery[][]) {
  const valid = histories.every(h => h.every(d => d.decrypted && d.authenticated));
  const records = histories.map(h => h.map(d => JSON.stringify(d.message)));
  const sets = records.map(r => JSON.stringify([...r].sort()));
  const messageSet = valid && sets.every(s => s === sets[0]);
  const totalOrder = messageSet && records.every(r => JSON.stringify(r) === JSON.stringify(records[0]));
  const senderOrders = histories.map(h => {
    const senders = [...new Set(h.map(d => d.message.sender))].sort();
    return JSON.stringify(senders.map(s => [s, h.filter(d => d.message.sender === s).map(d => d.message.id)]));
  });
  const senderOrder = messageSet && senderOrders.every(s => s === senderOrders[0]);
  // Declared toy reconciliation: honest users, unique edit IDs, assignment to
  // distinct named fields. No concurrent writes, rollback or permission model.
  const documents = histories.map(h => {
    const fields: Record<string,string> = {};
    for (const d of h) if (d.message.kind === 'edit') fields[d.message.field!] = d.message.value!;
    return JSON.stringify(Object.entries(fields).sort(([a],[b])=>a.localeCompare(b)));
  });
  const reconciled = messageSet && documents.every(s=>s===documents[0]);
  return { valid, messageSet, senderOrder, totalOrder, reconciled, documents };
}

/** A response must bind the entire question and ordered choices as well as the
 * selected option. An index or choice hash alone cannot identify a poll. */
export function pollBinding(poll: AppMessage, choice: number): string {
  if (poll.kind !== 'poll' || !poll.question || !poll.choices || !Number.isInteger(choice) || choice < 0 || choice >= poll.choices.length) throw new Error('Invalid poll response');
  return JSON.stringify({ pollId: poll.id, question: poll.question, choices: poll.choices, choice });
}

export async function simulateApplication(scenario: Scenario, epochKey: Uint8Array) {
  // Explicit separate transport model: real AES-GCM plus sender ECDSA P-256
  // signatures, rather than relying on the main teaching model's missing MLS
  // credential signatures/framing. These are NOT RFC 9420 wire messages.
  const epochCopies = [epochKey.slice(), epochKey.slice()];
  const key = await crypto.subtle.importKey('raw', epochKey, 'AES-GCM', false, ['encrypt','decrypt']);
  const signers = new Map<string, CryptoKeyPair>();
  for (const name of ['Mallory','Alice','Bob']) signers.set(name, await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'}, false, ['sign','verify']));
  const pollA: AppMessage = {id:'poll-1',sender:'Mallory',sequence:1,kind:'poll',question:'Keep the library open?',choices:['Yes','No']};
  const pollB = {...pollA,question:'Close the library?'};
  const a: AppMessage = {id:'edit-a',sender:'Alice',sequence:1,kind:'edit',field:'opening',value:'09:00'};
  const b: AppMessage = {id:'edit-b',sender:'Bob',sequence:1,kind:'edit',field:'closing',value:'18:00'};
  const sent = scenario === 'equivocation' ? [[pollA],[pollB]] :
    scenario === 'missing' ? [[a,b],[a]] : scenario === 'altered' ? [[a,b],[a,{...b,value:'17:00'}]] : [[a,b],[b,a]];
  async function deliver(message: AppMessage, corrupt: boolean): Promise<Delivery> {
    const bytes = new TextEncoder().encode(JSON.stringify(message));
    const signature = await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'}, signers.get(message.sender)!.privateKey, bytes);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv}, key, bytes));
    if (corrupt) encrypted[0] ^= 1;
    try {
      const plaintext = await crypto.subtle.decrypt({name:'AES-GCM',iv}, key, encrypted);
      const authenticated = await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'}, signers.get(message.sender)!.publicKey, signature, plaintext);
      return {message:JSON.parse(new TextDecoder().decode(plaintext)),decrypted:true,authenticated};
    } catch { return {message,decrypted:false,authenticated:false}; }
  }
  const histories: Delivery[][] = [];
  for (let recipient=0;recipient<sent.length;recipient++) {
    const received: Delivery[] = [];
    for (let i=0;i<sent[recipient].length;i++) received.push(await deliver(sent[recipient][i], scenario==='malformed' && recipient===1 && i===0));
    histories.push(received);
  }
  return {histories, ...compareHistories(histories), keysEqual:epochCopies[0].every((v,i)=>v===epochCopies[1][i]),
    weakResponsesEqual:pollA.choices![0]===pollB.choices![0],
    boundResponsesEqual:pollBinding(pollA,0)===pollBinding(pollB,0)};
}
