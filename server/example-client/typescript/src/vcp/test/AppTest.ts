// ------------------------------------------------------------------------------
import {AC2C_BBS, AC2C_PS, DNC, ApiError} from '../api';
import { IndexSignature3Level } from '../util';
import {TestData} from './TestData';
import {Util} from './Util';
import {SigType, X} from './X';
// ------------------------------------------------------------------------------
import * as GENERATED from 'VCP';
// ------------------------------------------------------------------------------
import { assert } from 'chai'
// ------------------------------------------------------------------------------

const emptyDecryptRequests : IndexSignature3Level<GENERATED.DecryptRequest> = {};

// ------------------------------------------------------------------------------

export function testRevealedAux(x : X) {
  Util.banner(x, "testRevealed");

  // Verifier
  x.credD.disclosed = TestData.DL_REVEALED;
  x.credS.disclosed = TestData.SUB_REVEALED;

  expect(x, emptyDecryptRequests);
}

export function testRevealedAC2C_BBS() {
  X.create(AC2C_BBS, SigType.NonBlinded) .then((x) => { testRevealedAux(x); })
  X.create(AC2C_BBS, SigType.Blinded)    .then((x) => { testRevealedAux(x); })
}

export function testRevealedAC2C_PS() {
  X.create(AC2C_PS, SigType.NonBlinded)  .then((x) => { testRevealedAux(x); })
  X.create(AC2C_PS, SigType.Blinded)     .then((x) => { testRevealedAux(x); })
}

export function testRevealedDNC() {
  X.create(DNC, SigType.NonBlinded)      .then((x) => { testRevealedAux(x); })
  X.create(DNC, SigType.Blinded)         .then((x) => { testRevealedAux(x); })
}

export function testRevealed() {
  testRevealedAC2C_BBS();
  testRevealedAC2C_PS();
  testRevealedDNC();
}

// ------------------------------------------------------------------------------

export function testEqualitiesAux(x : X) {
  Util.banner(x, "testEqualities");

  // Verifier
  x.credD.equalTo = [{fromIndex: 2, toLabel: TestData.SUB, toIndex: 3}];
  x.credS.equalTo = [{fromIndex: 3, toLabel: TestData.DL , toIndex: 2}];
  expect(x, emptyDecryptRequests);
}

export function testEqualitiesAC2C_BBS() {
  X.create(AC2C_BBS, SigType.NonBlinded) .then((x) => { testEqualitiesAux(x); })
  X.create(AC2C_BBS, SigType.Blinded)    .then((x) => { testEqualitiesAux(x); })

}

export function testEqualitiesAC2C_PS() {
  X.create(AC2C_PS, SigType.NonBlinded)  .then((x) => { testEqualitiesAux(x); })
  X.create(AC2C_PS, SigType.Blinded)     .then((x) => { testEqualitiesAux(x); })
}

export function testEqualitiesDNC() {
  X.create(DNC, SigType.NonBlinded)      .then((x) => { testEqualitiesAux(x); })
  X.create(DNC, SigType.Blinded)         .then((x) => { testEqualitiesAux(x); })
}

export function testEqualities() {
  testEqualitiesAC2C_BBS();
  testEqualitiesAC2C_PS();
  testEqualitiesDNC();
}

// ------------------------------------------------------------------------------

export function testRangeAux(x : X) {
  Util.banner(x, "testRange");

  // Verifier
  x.ci.createRangeProofProvingKey(0).then((rpk) => {
    const dira : GENERATED.InRangeInfo[] = [{
      index                : TestData.DL_IN_RANGE_INDEX,
      minLabel             : TestData.DL_RANGE_MIN,
      maxLabel             : TestData.DL_RANGE_MAX,
      rangeProvingKeyLabel : TestData.DL_RPPK }];
    const sira : GENERATED.InRangeInfo[] = [{
      index                : TestData.SUB_IN_RANGE_INDEX,
      minLabel             : TestData.SUB_RANGE_MIN,
      maxLabel             : TestData.SUB_RANGE_MAX,
      rangeProvingKeyLabel : TestData.DL_RPPK }];
    x.credD.inRange = dira;
    x.credS.inRange = sira;
    x.shared.set(TestData.DL_RPPK,       Util.mkSPVOneText(Util.quote(rpk)));
    x.shared.set(TestData.DL_RANGE_MIN,  Util.mkSPVOneInt(37696));
    x.shared.set(TestData.DL_RANGE_MAX,  Util.mkSPVOneInt(999999999));

    x.shared.set(TestData.SUB_RPPK,      Util.mkSPVOneText(Util.quote(rpk)));
    x.shared.set(TestData.SUB_RANGE_MIN, Util.mkSPVOneInt(0));
    x.shared.set(TestData.SUB_RANGE_MAX, Util.mkSPVOneInt(49998));

    expect(x, emptyDecryptRequests);
  });
}

export function testRangeAC2C_BBS() {
  X.create(AC2C_BBS, SigType.NonBlinded) .then((x) => { testRangeAux(x); })
  X.create(AC2C_BBS, SigType.Blinded)    .then((x) => { testRangeAux(x); })
}

export function testRangeAC2C_PS() {
  X.create(AC2C_PS, SigType.NonBlinded)  .then((x) => { testRangeAux(x); })
  X.create(AC2C_PS, SigType.Blinded)     .then((x) => { testRangeAux(x); })
}

export function testRangeDNC() {
  X.create(DNC, SigType.NonBlinded)      .then((x) => { testRangeAux(x); })
  X.create(DNC, SigType.Blinded)         .then((x) => { testRangeAux(x); })
}

export function testRange() {
  testRangeAC2C_BBS();
  testRangeAC2C_PS();
  testRangeDNC();
}

// ------------------------------------------------------------------------------

export function testVerifiableEncryptionAux(x : X) {
  Util.banner(x, "testVerifiableEncryption");

  // Authority
  x.ci.createAuthorityData(0).then((ad) => {

    // Verifier
    x.shared.set(TestData.AUTH_LABEL,
                 Util.mkSPVOneText(Util.quote(ad.authorityPublicData)));
    x.credD.encryptedFor = [{ index : 2, label : TestData.AUTH_LABEL }];
    x.credS.encryptedFor = [{ index : 3, label : TestData.AUTH_LABEL }];
    // Authority
    // Note: CredAttrIndex gets turned into String by OpenAPI
    const drs : IndexSignature3Level<GENERATED.DecryptRequest> = {
      [TestData.DL]: {
        "2": {
          [TestData.AUTH_LABEL]: {
            authoritySecretData    : ad.authoritySecretData,
            authorityDecryptionKey : ad.authorityDecryptionKey
          }
        }
      },
      [TestData.SUB]: {
        "3": {
          [TestData.AUTH_LABEL]: {
            authoritySecretData    : ad.authoritySecretData,
            authorityDecryptionKey : ad.authorityDecryptionKey
          }
        }
      }
    };
    expect(x, drs);
  });
}

export function checkAC2CVerifiableEncryptionException(e : Error) {
  assert.strictEqual((e as ApiError).apiErrorMessage.reason,
                     'General("specific_verify_decryption_ac2c : UNIMPLEMENTED")');
  console.log("AC2C failed verify_decryption as expected");
}

export function testVerifiableEncryptionAC2C_BBS() {
  X.create(AC2C_BBS, SigType.NonBlinded) .then((x) => {
    try { testVerifiableEncryptionAux(x); } catch (e) { checkAC2CVerifiableEncryptionException(e as Error); }})
  X.create(AC2C_BBS, SigType.Blinded)    .then((x) => {
    try { testVerifiableEncryptionAux(x); } catch (e) { checkAC2CVerifiableEncryptionException(e as Error); }})

}

export function testVerifiableEncryptionAC2C_PS() {
  X.create(AC2C_PS, SigType.NonBlinded)  .then((x) => {
    try { testVerifiableEncryptionAux(x); } catch (e) { checkAC2CVerifiableEncryptionException(e as Error); }})
  X.create(AC2C_PS, SigType.Blinded)     .then((x) => {
    try { testVerifiableEncryptionAux(x); } catch (e) { checkAC2CVerifiableEncryptionException(e as Error); }})

}

export function testVerifiableEncryptionDNCNonBlinded() {
  X.create(DNC, SigType.NonBlinded)      .then((x) => { testVerifiableEncryptionAux(x); })
}

export function testVerifiableEncryptionDNCBlinded() {
  X.create(DNC, SigType.Blinded)         .then((x) => { testVerifiableEncryptionAux(x); })
}

export function testVerifiableEncryptionDNC() {
  testVerifiableEncryptionDNCNonBlinded();
  testVerifiableEncryptionDNCBlinded();
}

export function testVerifiableEncryption() {
  testVerifiableEncryptionAC2C_BBS();
  testVerifiableEncryptionAC2C_PS();
  testVerifiableEncryptionDNC();
}

// ------------------------------------------------------------------------------

// This tests
// - create an accumulator and add initial elements
// TODO: accumulator updates
export function testAccumulatorsAux(x : X)  {
  Util.banner(x, "testAccumulators");

  Promise.all([
    // Revocation manager
    x.ci.createMembershipProvingKey(0),
    x.ci.createAccumulatorData(0),
    x.ci.createAccumulatorData(1),
    // Issuer in conjunction with Revocation manager
    x.ci.createAccumulatorElement(TestData.DL_ACC_MEM_VALUE),
    x.ci.createAccumulatorElement(TestData.SUB_ACC_MEM_VALUE),
  ]).then(([mpk, dCar, sCar, dAccElem, sAccElem]) => {
    const dApd  = dCar.accumulatorData.accumulatorPublicData;
    const sApd  = sCar.accumulatorData.accumulatorPublicData;
    Promise.all([
      x.ci.accumulatorAddRemove(dCar.accumulatorData, dCar.accumulator,
                                { [TestData.DL_HOLDER_ID]  : dAccElem }, []),
      x.ci.accumulatorAddRemove(sCar.accumulatorData, sCar.accumulator,
                                { [TestData.SUB_HOLDER_ID] : sAccElem }, []),
    ]).then(([dAddRmResp, sAddRmResp]) => {
      const dWit       = dAddRmResp.witnessesForNew[TestData.DL_HOLDER_ID];
      const sWit       = sAddRmResp.witnessesForNew[TestData.SUB_HOLDER_ID];

      // Ensure same witness
      x.ci.getAccumulatorWitness(dCar.accumulatorData, dAddRmResp.accumulator, dAccElem).then((dWitViaGet) => {
        assert.equal(dWit, dWitViaGet, "AddRemove and Get should be the same");
      });

      // Holder in conjunction with Issuer and Revocation Manager
      x.dSard.accumulatorWitnesses = { [ TestData.DL_ACC_INDEX_STR ] : dWit };
      x.sSard.accumulatorWitnesses = { [ TestData.SUB_ACC_INDEX_STR] : sWit };
        // Verifier
      x.shared.set(TestData.DL_APD,
                   Util.mkSPVOneText(Util.quote(dApd)));
      x.shared.set(TestData.DL_ACC,
                   Util.mkSPVOneText(Util.quote(dAddRmResp.accumulator)));
      x.shared.set(TestData.DL_MPK,
                   Util.mkSPVOneText(Util.quote(mpk)));

      x.shared.set(TestData.SUB_APD,
                   Util.mkSPVOneText(Util.quote(sApd)));
      x.shared.set(TestData.SUB_ACC,
                   Util.mkSPVOneText(Util.quote(sAddRmResp.accumulator)));
      x.shared.set(TestData.SUB_MPK,
                   Util.mkSPVOneText(Util.quote(mpk)));

      x.shared.set(TestData.DL_ACC_SEQ_NUM_LABEL,
                   Util.mkSPVOneInt(TestData.DL_ACC_SEQ_NUM));
      x.shared.set(TestData.SUB_ACC_SEQ_NUM_LABEL,
                   Util.mkSPVOneInt(TestData.SUB_ACC_SEQ_NUM));

      x.credD.inAccum = [{
        index                      : TestData.DL_ACC_INDEX,
        membershipProvingKeyLabel  : TestData.DL_MPK,
        accumulatorPublicDataLabel : TestData.DL_APD,
        accumulatorLabel           : TestData.DL_ACC,
        accumulatorSeqNumLabel     : TestData.DL_ACC_SEQ_NUM_LABEL
      }];
      x.credS.inAccum = [{
        index                      : TestData.SUB_ACC_INDEX,
        membershipProvingKeyLabel  : TestData.SUB_MPK,
        accumulatorPublicDataLabel : TestData.SUB_APD,
        accumulatorLabel           : TestData.SUB_ACC,
        accumulatorSeqNumLabel     : TestData.SUB_ACC_SEQ_NUM_LABEL,
      }];

      expect(x, emptyDecryptRequests);

    });
  });
}

export function testAccumulatorsAC2C_BBS() {
  X.create(AC2C_BBS, SigType.NonBlinded) .then((x) => { testAccumulatorsAux(x); })
  X.create(AC2C_BBS, SigType.Blinded)    .then((x) => { testAccumulatorsAux(x); })
}

export function testAccumulatorsAC2C_PS() {
  X.create(AC2C_PS, SigType.NonBlinded)  .then((x) => { testAccumulatorsAux(x); })
  X.create(AC2C_PS, SigType.Blinded)     .then((x) => { testAccumulatorsAux(x); })
}

export function testAccumulatorsDNC() {
  X.create(DNC, SigType.NonBlinded)      .then((x) => { testAccumulatorsAux(x); })
  X.create(DNC, SigType.Blinded)         .then((x) => { testAccumulatorsAux(x); })
}

export function testAccumulators() {
  testAccumulatorsAC2C_BBS();
  testAccumulatorsAC2C_PS();
  testAccumulatorsDNC();
}

// ------------------------------------------------------------------------------

function expect(
  x : X,
  decryptRequests : IndexSignature3Level<GENERATED.DecryptRequest>
) {
  Util.banner(x, "expect");
  Util.sop("reqs", x.reqs);
  // Util.sop("shared", shared); // authority key TOO BIG

  // Issuer
  X.doCreateProof(x).then((wadfv) => {
    Util.sop("wadfv", wadfv);
    assert.isEmpty(wadfv.warnings);
    checkDisclosed(x, wadfv.dataForVerifier);

    // Verifier and Authority
    X.doVerifyProof(x, wadfv.dataForVerifier, decryptRequests).then((wadr) => {
      Util.sop("wadr", wadr);
      assert.isEmpty(wadr.warnings);
      checkDecryption(decryptRequests, wadr.decryptResponses);

      // Governance body
      if (! isEmpty(wadr.decryptResponses)) {
        verifyDecryption(x, wadfv.dataForVerifier,
                         decryptRequests, wadr.decryptResponses, TestData.NONCE);
      }
    })
  })
}

function checkDisclosed(x : X, dfv : GENERATED.DataForVerifier) {
  const reqD  = x.credD.disclosed;
  const reqS  = x.credS.disclosed;
  const rev   = dfv.revealedIdxsAndVals;
  const revD  = rev[TestData.DL];
  const revS  = rev[TestData.SUB];
  // TODO : check indices and values
  if (isEmpty(reqD) && isEmpty(reqS)) {
    assert.isTrue( isEmpty(revD) &&  isEmpty(revS));
  } else {
    assert.isTrue(!isEmpty(revD) || !isEmpty(revS));
  }
}

function checkDecryption(
  decryptRequests  : IndexSignature3Level<GENERATED.DecryptRequest>,
  decryptResponses : IndexSignature3Level<GENERATED.DecryptResponse>,
) {
  for (const credLabel in decryptRequests) {
    for (const attrIndex in decryptRequests[credLabel]) {
      for (const authLabel in decryptRequests[credLabel][attrIndex]) {
        const rsp = decryptResponses[credLabel][attrIndex][authLabel];
        const decoded = rsp.value;
        Util.sop("decryption", credLabel + " " + attrIndex + " " + authLabel + " " + decoded);
        let vals = null;
        if (credLabel === TestData.DL) {
          vals = TestData.dVals();
        } else if (credLabel === TestData.SUB) {
          vals = TestData.sVals();
        } else {
          throw Error("test misconfigured: " + credLabel);
        }
        assert.strictEqual(vals[attrIndex as unknown as number].contents,   // .DVText.contents,
                           decoded);
      }
    }
  }
}

function verifyDecryption(
  x                : X,
  dfv              : GENERATED.DataForVerifier,
  decryptRequests  : IndexSignature3Level<GENERATED.DecryptRequest>,
  decryptResponses : IndexSignature3Level<GENERATED.DecryptResponse>,
  nonce            : string
) {
  Util.banner(x, "verifyDecryption");
  const adks = new Map<string, string>();
  for (const credLabel in decryptRequests) {
    for (const attrIndex in decryptRequests[credLabel]) {
      for (const authLabel in decryptRequests[credLabel][attrIndex]) {
        const dr = decryptRequests[credLabel][attrIndex][authLabel];
        adks.set(authLabel, Util.quote(dr.authorityDecryptionKey));
      }
    }
  }
  x.ci.verifyDecryption(x.reqs, x.shared, dfv.proof, adks, decryptResponses, nonce)
    .then( (w) => {
      assert.strictEqual(w, []);
    })
    .catch((e) => checkAC2CVerifiableEncryptionException(e));
}

// https://stackoverflow.com/a/77410695/814846
type Falsy = false | 0 | 0n | "" | null | undefined;

function isEmpty(obj: any) : obj is Falsy | never[] | { [k: string]: never }
{
  return !obj
    || (Array.isArray(obj) && !obj.length)
    || !Object.getOwnPropertyNames(obj).length;
}
