import { describe, it, expect } from 'vitest';
import { simulateApplication, pollBinding, compareHistories } from '../group/application-consistency';
import { createInitialGroupState } from '../group/group-state';

describe('application consistency is independent of key convergence',()=>{
  const key = new Uint8Array(32).fill(7);
  it('accepts authentic poll messages while detecting incompatible meanings',async()=>{
    const r=await simulateApplication('equivocation',key);
    expect(r.keysEqual).toBe(true);expect(r.valid).toBe(true);expect(r.messageSet).toBe(false);
    expect(r.weakResponsesEqual).toBe(true);expect(r.boundResponsesEqual).toBe(false);
  });
  it('reconciles identical edit sets despite different total orders',async()=>{
    const r=await simulateApplication('honest',key);
    expect(r.valid).toBe(true);expect(r.messageSet).toBe(true);expect(r.senderOrder).toBe(true);
    expect(r.totalOrder).toBe(false);expect(r.reconciled).toBe(true);
  });
  it.each(['missing','altered','malformed'] as const)('does not bless %s delivery',async scenario=>{
    const r=await simulateApplication(scenario,key);
    expect(r.keysEqual).toBe(true);expect(r.reconciled).toBe(false);expect(r.messageSet).toBe(false);
    expect(r.valid).toBe(scenario!=='malformed');
  });
  it('retains independently stored recipient application histories',async()=>{
    const s=createInitialGroupState();await s.sendApplication(0,'A first message');
    const leaves=s.activeMembers();expect(leaves.length).toBeGreaterThan(1);
    expect(s.applicationHistories.get(leaves[0])).toHaveLength(1);
    s.applicationHistories.get(leaves[0])!.pop();
    expect(s.applicationHistories.get(leaves[1])).toHaveLength(1);
  });
  it('rejects invalid poll indices',()=>{
    expect(()=>pollBinding({id:'p',sender:'a',sequence:1,kind:'poll',question:'Q?',choices:['yes']},1)).toThrow();
  });
  it('checks same-sender order separately and binds ordered choices',()=>{
    const a={message:{id:'a',sender:'Alice',sequence:1,kind:'edit' as const,field:'opening',value:'09:00'},decrypted:true,authenticated:true};
    const b={message:{id:'b',sender:'Alice',sequence:2,kind:'edit' as const,field:'closing',value:'18:00'},decrypted:true,authenticated:true};
    const r=compareHistories([[a,b],[b,a]]);
    expect(r.messageSet).toBe(true);expect(r.senderOrder).toBe(false);expect(r.totalOrder).toBe(false);
    const poll={id:'p',sender:'M',sequence:1,kind:'poll' as const,question:'Q?',choices:['yes','no']};
    expect(pollBinding(poll,0)).not.toBe(pollBinding({...poll,choices:['no','yes']},0));
  });
});
