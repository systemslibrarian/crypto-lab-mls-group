import { GroupStateModel } from '../group/group-state';
import { memberName } from '../group/members';
import { simulateApplication } from '../group/application-consistency';
import type { Scenario } from '../group/application-consistency';

export function renderApplicationConsistency(state: GroupStateModel): HTMLElement {
  const panel = document.createElement('section'); panel.className='panel';
  panel.setAttribute('aria-labelledby','app-consistency-title');
  panel.innerHTML=`<h2 id="app-consistency-title">Same epoch key, different conversations</h2>
    <p>Key convergence and application-message consistency are separate properties. The protocol event log above is not each recipient's received history.</p>
    <details><summary>Current recipients' application histories</summary><div id="recipient-histories"></div></details>
    <h3>Compare an explicit authenticated application model</h3>
    <p>This isolated experiment copies the current epoch's encryption key and uses real AES-GCM and ECDSA P-256 sender signatures. It does not implement MLS framing or credential authentication. The main MLS teaching model still omits credential signatures, authenticated framing and confirmation tags.</p>
    <label for="app-scenario">Delivery scenario</label><select id="app-scenario">
    <option value="equivocation">Malicious member sends differently worded polls</option><option value="honest">Honest users, same edits in different arrival orders</option>
    <option value="missing">Missing edit</option><option value="altered">Authorized sender changes an edit</option><option value="malformed">Malformed ciphertext control</option></select>
    <button type="button" id="app-compare">Compare recipient views</button><div id="app-result" aria-live="polite"></div>
    <p>An honest server delivers the member's addressed messages; no network forgery is needed for the poll disagreement. An option index or a choice hash cannot bind the question. A bound response includes poll ID, question, ordered choices and selected option.</p>
    <p>Checks shown: message-set equality, per-sender order and total arrival order. Causal consistency is not evaluated. Honest edit reconciliation here means unique edits to distinct fields; it does not model general collaborative documents, rollback, conflicting writes or fine-grained permissions. Missing or altered edit sets cannot earn reconciliation success.</p>
    <p>Sources: <a href="https://www.usenix.org/conference/usenixsecurity26/presentation/gegenhuber" target="_blank" rel="noopener noreferrer">Send and Pretend</a> (pp. 4–5, 9–14, 20–21) and <a href="https://www.usenix.org/conference/usenixsecurity26/presentation/knabenhans" target="_blank" rel="noopener noreferrer">End-to-End Encrypted Collaborative Documents</a> (pp. 3–5, 12–13, 20–21). This adaptation is not a break of production MLS or a reproduction of either paper.</p>`;
  const histories=panel.querySelector('#recipient-histories')!;
  for(const leaf of state.activeMembers()) {
    const p=document.createElement('p');
    const messages=state.applicationHistories.get(leaf)??[];
    p.textContent=`${memberName(leaf)}: ${messages.length ? messages.map(e=>`epoch ${e.epoch}: ${e.detail}`).join(' | ') : 'No application messages received.'}`;
    histories.append(p);
  }
  const button=panel.querySelector<HTMLButtonElement>('#app-compare')!;
  button.addEventListener('click',async()=>{
    button.disabled=true;
    const output=panel.querySelector('#app-result')!;
    try {
      const scenario=panel.querySelector<HTMLSelectElement>('#app-scenario')!.value as Scenario;
      const result=await simulateApplication(scenario,state.epochSecrets.encryption.slice());
      output.replaceChildren();
      const p=document.createElement('p');
      p.textContent=`Equal epoch keys: ${result.keysEqual}. All decryptions and sender signatures valid: ${result.valid}. Message sets equal: ${result.messageSet}. Sender order equal: ${result.senderOrder}. Total order equal: ${result.totalOrder}.`;
      output.append(p);
      result.histories.forEach((history,i)=>{
        const h=document.createElement('h4');h.textContent=`Recipient ${i===0?'Alice':'Bob'}`;output.append(h);
        const list=document.createElement('ol');
        for(const d of history){const item=document.createElement('li');item.textContent=`${d.message.sender}: ${d.message.kind==='poll'?`${d.message.question} [${d.message.choices!.join(', ')}]`:`${d.message.field} = ${d.message.value}`} — decrypt ${d.decrypted}, signature ${d.authenticated}`;list.append(item);}output.append(list);
      });
      const meaning=document.createElement('p');
      meaning.textContent=scenario==='equivocation'?`Both vote “Yes” (index 0), but one approves keeping the library open and one approves closing it. Index-only responses equal: ${result.weakResponsesEqual}. Full poll-bound responses equal: ${result.boundResponsesEqual}.`:`Same edit set and reconciled document: ${result.reconciled}. Alice ${result.documents[0]}; Bob ${result.documents[1]}.`;
      output.append(meaning);
    } catch(e) {output.textContent=`Experiment failed: ${e instanceof Error?e.message:String(e)}`;}
    finally {button.disabled=false;}
  });
  return panel;
}
