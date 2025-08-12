package com.example.vcp.demos;

// ---------------------------------------------------------------------------
//import com.example.vcp.client.api.DefaultApi;
import com.example.vcp.client.ApiException;
import com.example.vcp.client.model.*;
// ---------------------------------------------------------------------------
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
// ---------------------------------------------------------------------------
import java.io.IOException;
import java.util.*;
// ---------------------------------------------------------------------------

public class AppTest
        extends TestCase {
    private Map<String, Map<String, Map<String, DecryptRequest>>> emptyDecryptRequests = new HashMap<>();

    public AppTest(final String testName) { super(testName); }

    public static Test suite() { return new TestSuite(AppTest.class); }

    // ------------------------------------------------------------------------------

    public void testRevealedAux(final X x) throws ApiException, IOException {
        Util.banner(x, "testRevealed");

        // Verifier
        x.credD.disclosed(TestData.DL_REVEALED);
        x.credS.disclosed(TestData.SUB_REVEALED);

        expect(x, emptyDecryptRequests);
    }

    public void testRevealedAC2C_BBS() throws ApiException, IOException {
        testRevealedAux(new X(TestData.AC2C_BBS, X.SigType.NonBlinded));
        testRevealedAux(new X(TestData.AC2C_BBS, X.SigType.Blinded));
    }
    public void testRevealedAC2C_PS()  throws ApiException, IOException {
        testRevealedAux(new X(TestData.AC2C_PS,  X.SigType.NonBlinded));
        testRevealedAux(new X(TestData.AC2C_PS,  X.SigType.Blinded));
    }
    public void testRevealedDNC()      throws ApiException, IOException {
        testRevealedAux(new X(TestData.DNC,      X.SigType.NonBlinded));
        testRevealedAux(new X(TestData.DNC,      X.SigType.Blinded));
    }
    public void testRevealed()         throws ApiException, IOException {
        testRevealedAC2C_BBS();
        testRevealedAC2C_PS();
        testRevealedDNC();
    }

    // ------------------------------------------------------------------------------

    public void testEqualitiesAux(final X x) throws ApiException, IOException {
        Util.banner(x, "testEqualities");

        // Verifier
        final EqInfo[] deqa = { new EqInfo().fromIndex(2).toLabel(TestData.SUB).toIndex(3) };
        final EqInfo[] seqa = { new EqInfo().fromIndex(3).toLabel(TestData.DL).toIndex(2) };
        x.credD.equalTo(Arrays.asList(deqa));
        x.credS.equalTo(Arrays.asList(seqa));

        expect(x, emptyDecryptRequests);
    }

    public void testEqualitiesAC2C_BBS() throws ApiException, IOException {
        testEqualitiesAux(new X(TestData.AC2C_BBS, X.SigType.NonBlinded));
        testEqualitiesAux(new X(TestData.AC2C_BBS, X.SigType.Blinded));
    }
    public void testEqualitiesAC2C_PS()  throws ApiException, IOException {
        testEqualitiesAux(new X(TestData.AC2C_PS,  X.SigType.NonBlinded));
        testEqualitiesAux(new X(TestData.AC2C_PS,  X.SigType.Blinded));
    }
    public void testEqualitiesDNC()      throws ApiException, IOException {
        testEqualitiesAux(new X(TestData.DNC,      X.SigType.NonBlinded));
        testEqualitiesAux(new X(TestData.DNC,      X.SigType.Blinded));
    }
    public void testEqualities()         throws ApiException, IOException {
        testEqualitiesAC2C_BBS();
        testEqualitiesAC2C_PS();
        testEqualitiesDNC();
    }

    // ------------------------------------------------------------------------------

    public void testRangeAux(final X x) throws ApiException, IOException {
        Util.banner(x, "testRange");

        // Verifier
        final var rpk            = x.api.createRangeProofProvingKey(x.zkpLib, 0);
        final InRangeInfo[] dira = { new InRangeInfo()
            .index(TestData.DL_IN_RANGE_INDEX)
            .minLabel(TestData.DL_RANGE_MIN)
            .maxLabel(TestData.DL_RANGE_MAX)
            .rangeProvingKeyLabel(TestData.DL_RPPK) };
        final InRangeInfo[] sira = { new InRangeInfo()
            .index(TestData.SUB_IN_RANGE_INDEX)
            .minLabel(TestData.SUB_RANGE_MIN)
            .maxLabel(TestData.SUB_RANGE_MAX)
            .rangeProvingKeyLabel(TestData.DL_RPPK) };
        x.credD.inRange(Arrays.asList(dira));
        x.credS.inRange(Arrays.asList(sira));
        x.shared.put(TestData.DL_RPPK,       Util.mkSPVOneText(Util.quote(rpk)));
        x.shared.put(TestData.DL_RANGE_MIN,  Util.mkSPVOneLong(37696));
        x.shared.put(TestData.DL_RANGE_MAX,  Util.mkSPVOneLong(999999999));

        x.shared.put(TestData.SUB_RPPK,      Util.mkSPVOneText(Util.quote(rpk)));
        x.shared.put(TestData.SUB_RANGE_MIN, Util.mkSPVOneLong(0));
        x.shared.put(TestData.SUB_RANGE_MAX, Util.mkSPVOneLong(49998));

        expect(x, emptyDecryptRequests);
    }

    public void testRangeAC2C_BBS() throws ApiException, IOException {
        testRangeAux(new X(TestData.AC2C_BBS, X.SigType.NonBlinded));
        testRangeAux(new X(TestData.AC2C_BBS, X.SigType.Blinded));
    }
    public void testRangeAC2C_PS()  throws ApiException, IOException {
        testRangeAux(new X(TestData.AC2C_PS,  X.SigType.NonBlinded));
        testRangeAux(new X(TestData.AC2C_PS,  X.SigType.Blinded));
    }
    public void testRangeDNC()      throws ApiException, IOException {
        testRangeAux(new X(TestData.DNC,      X.SigType.NonBlinded));
        testRangeAux(new X(TestData.DNC,      X.SigType.Blinded));
    }
    public void testRange()         throws ApiException, IOException {
        testRangeAC2C_BBS();
        testRangeAC2C_PS();
        testRangeDNC();
    }

    // ------------------------------------------------------------------------------

    public void testVerifiableEncryptionAux(final X x) throws ApiException, IOException {
        Util.banner(x, "testVerifiableEncryption");
        x.api.getApiClient().setReadTimeout(30 * 60 * 1000);

        // Authority
        final var ad = x.api.createAuthorityData(x.zkpLib, 0);

        // Verifier
        x.shared.put(TestData.AUTH_LABEL,
                Util.mkSPVOneText(Util.quote(ad.getAuthorityPublicData())));
        final IndexAndLabel[] daa = { new IndexAndLabel().index(2).label(TestData.AUTH_LABEL) };
        final IndexAndLabel[] saa = { new IndexAndLabel().index(3).label(TestData.AUTH_LABEL) };
        x.credD.encryptedFor(Arrays.asList(daa));
        x.credS.encryptedFor(Arrays.asList(saa));

        // Authority
        // Note: CredAttrIndex gets turned into String by OpenAPI
        final var drs = Map.of(TestData.DL,
                Map.of("2",
                        Map.of(TestData.AUTH_LABEL,
                                new DecryptRequest()
                                        .authoritySecretData(ad.getAuthoritySecretData())
                                        .authorityDecryptionKey(ad.getAuthorityDecryptionKey()))),
                TestData.SUB,
                Map.of("3",
                        Map.of(TestData.AUTH_LABEL,
                                new DecryptRequest()
                                        .authoritySecretData(ad.getAuthoritySecretData())
                                        .authorityDecryptionKey(ad.getAuthorityDecryptionKey()))));
        expect(x, drs);
    }

    static void checkAC2CVerifiableEncryptionException(final ApiException e) {
        assertEquals("code", 400, e.getCode());
        assertTrue("reason", e.getMessage().contains("specific_verify_decryption_ac2c : UNIMPLEMENTED"));
        System.out.println("AC2C failed verify_decryption as expected");
    }
    public void testVerifiableEncryptionAC2C_BBS() throws ApiException, IOException {
        try {
            testVerifiableEncryptionAux(new X(TestData.AC2C_BBS, X.SigType.NonBlinded));
        } catch (ApiException e) {
            checkAC2CVerifiableEncryptionException(e);
        }
        try {
            testVerifiableEncryptionAux(new X(TestData.AC2C_BBS, X.SigType.Blinded));
        } catch (ApiException e) {
            checkAC2CVerifiableEncryptionException(e);
        }
    }
    public void testVerifiableEncryptionAC2C_PS()  throws ApiException, IOException {
        try {
            testVerifiableEncryptionAux(new X(TestData.AC2C_PS,  X.SigType.NonBlinded));
        } catch (ApiException e) {
            checkAC2CVerifiableEncryptionException(e);
        }
        try {
            testVerifiableEncryptionAux(new X(TestData.AC2C_PS,  X.SigType.Blinded));
        } catch (ApiException e) {
            checkAC2CVerifiableEncryptionException(e);
        }
    }
    public void testVerifiableEncryptionAC2C()         throws ApiException, IOException {
        testVerifiableEncryptionAC2C_BBS();
        testVerifiableEncryptionAC2C_PS();
    }
    public void testVerifiableEncryptionDNC()      throws ApiException, IOException {
        testVerifiableEncryptionAux(new X(TestData.DNC,      X.SigType.NonBlinded));
        testVerifiableEncryptionAux(new X(TestData.DNC,      X.SigType.Blinded));
    }
    public void testVerifiableEncryption()         throws ApiException, IOException {
        testVerifiableEncryptionAC2C_BBS();
        testVerifiableEncryptionAC2C_PS();
        testVerifiableEncryptionDNC();
    }

    // ------------------------------------------------------------------------------

    // This tests
    // - create an accumulator and add initial elements
    // TODOO: accumulator updates
    public void testAccumulatorsAux(final X x) throws ApiException, IOException {
        Util.banner(x, "testAccumulators");

        // Revocation manager
        final var mpk        = x.api.createMembershipProvingKey(x.zkpLib, 0);

        final var dCar       = x.api.createAccumulatorData(x.zkpLib, 0);
        final var sCar       = x.api.createAccumulatorData(x.zkpLib, 1);

        final var dApd       = dCar.getAccumulatorData().getAccumulatorPublicData();
        final var sApd       = sCar.getAccumulatorData().getAccumulatorPublicData();

        // Issuer in conjunction with Revocation manager
        final var dAccElem   = x.api.createAccumulatorElement(x.zkpLib, TestData.DL_ACC_MEM_VALUE);
        final var sAccElem   = x.api.createAccumulatorElement(x.zkpLib, TestData.SUB_ACC_MEM_VALUE);

        final var dAddRmResp = x.api.accumulatorAddRemove
            (x.zkpLib,
             new AccumulatorAddRemoveRequest()
             .accumulator(dCar.getAccumulator())
             .accumulatorData(dCar.getAccumulatorData())
             .additions(Map.of(TestData.DL_HOLDER_ID, dAccElem)));
        final var sAddRmResp = x.api.accumulatorAddRemove
            (x.zkpLib,
             new AccumulatorAddRemoveRequest()
             .accumulator(sCar.getAccumulator())
             .accumulatorData(sCar.getAccumulatorData())
             .additions(Map.of(TestData.SUB_HOLDER_ID, sAccElem)));
        Util.sop("dAddRmResp", dAddRmResp);
        Util.sop("sAddRmResp", sAddRmResp);

        final var dWit       = dAddRmResp.getWitnessesForNew().get(TestData.DL_HOLDER_ID);
        final var sWit       = sAddRmResp.getWitnessesForNew().get(TestData.SUB_HOLDER_ID);
        Util.sop("dWit", dWit);
        Util.sop("sWit", sWit);

        // Ensure same witness.
        final var getWitReq  = new GetAccumulatorWitnessRequest()
            .accumulator(dAddRmResp.getAccumulator())
            .accumulatorData(dCar.getAccumulatorData())
            .accumulatorElement(dAccElem);
        final var dWitViaGet = x.api.getAccumulatorWitness(x.zkpLib, getWitReq);
        assertEquals("AddRemove and Get should be the same", dWit, dWitViaGet);

        // Holder in conjunction with Issuer and Revocation Manager
        x.dSard.setAccumulatorWitnesses(Map.of(TestData.DL_ACC_INDEX_STR, dWit));
        x.sSard.setAccumulatorWitnesses(Map.of(TestData.SUB_ACC_INDEX_STR, sWit));
        Util.sop("dSard", x.dSard);
        Util.sop("sSard", x.sSard);

        // Verifier
        x.shared.put(TestData.DL_APD,
                     Util.mkSPVOneText(Util.quote(dApd)));
        x.shared.put(TestData.DL_ACC,
                     Util.mkSPVOneText(Util.quote(dAddRmResp.getAccumulator())));
        x.shared.put(TestData.DL_MPK,
                     Util.mkSPVOneText(Util.quote(mpk)));

        x.shared.put(TestData.SUB_APD,
                     Util.mkSPVOneText(Util.quote(sApd)));
        x.shared.put(TestData.SUB_ACC,
                     Util.mkSPVOneText(Util.quote(sAddRmResp.getAccumulator())));
        x.shared.put(TestData.SUB_MPK,
                     Util.mkSPVOneText(Util.quote(mpk)));


        x.shared.put(TestData.DL_ACC_SEQ_NUM_LABEL,
                     Util.mkSPVOneLong(TestData.DL_ACC_SEQ_NUM));
        x.shared.put(TestData.SUB_ACC_SEQ_NUM_LABEL,
                     Util.mkSPVOneLong(TestData.SUB_ACC_SEQ_NUM));

        x.credD.inAccum(Arrays.asList(new InAccumInfo()
                                      .index(TestData.DL_ACC_INDEX)
                                      .membershipProvingKeyLabel(TestData.DL_MPK)
                                      .accumulatorPublicDataLabel(TestData.DL_APD)
                                      .accumulatorSeqNumLabel(TestData.DL_ACC_SEQ_NUM_LABEL)
                                      .accumulatorLabel(TestData.DL_ACC)));
        x.credS.inAccum(Arrays.asList(new InAccumInfo()
                                      .index(TestData.SUB_ACC_INDEX)
                                      .membershipProvingKeyLabel(TestData.SUB_MPK)
                                      .accumulatorPublicDataLabel(TestData.SUB_APD)
                                      .accumulatorSeqNumLabel(TestData.SUB_ACC_SEQ_NUM_LABEL)
                                      .accumulatorLabel(TestData.SUB_ACC)));;

        expect(x, emptyDecryptRequests);
    }

    public void testAccumulatorsAC2C_BBS() throws ApiException, IOException {
        testAccumulatorsAux(new X(TestData.AC2C_BBS, X.SigType.NonBlinded));
        testAccumulatorsAux(new X(TestData.AC2C_BBS, X.SigType.Blinded));
    }
    public void testAccumulatorsAC2C_PS()  throws ApiException, IOException {
        testAccumulatorsAux(new X(TestData.AC2C_PS,  X.SigType.NonBlinded));
        testAccumulatorsAux(new X(TestData.AC2C_PS,  X.SigType.Blinded));
    }
    public void testAccumulatorsDNC()      throws ApiException, IOException {
        testAccumulatorsAux(new X(TestData.DNC,      X.SigType.NonBlinded));
        testAccumulatorsAux(new X(TestData.DNC,      X.SigType.Blinded));
    }
    public void testAccumulators()         throws ApiException, IOException {
        testAccumulatorsAC2C_BBS();
        testAccumulatorsAC2C_PS();
        testAccumulatorsDNC();
    }

    // ---------------------------------------------------------------------------

    public static void expect(
      final X x,
      final Map<String, Map<String, Map<String, DecryptRequest>>> decryptRequests)
        throws ApiException, IOException
    {
        Util.banner(x, "expect");
        Util.sop("reqs", x.reqs);
        // Util.sop("shared", shared); // authority key TOO BIG

        // Issuer
        final var wadfv = X.doCreateProof(x);
        Util.sop("wadfv", wadfv);
        assertEquals("createProof warnings", new ArrayList<Warning>(), wadfv.getWarnings());
        checkDisclosed(x, wadfv.getDataForVerifier());

        // Verifier and Authority
        final var wadr = X.doVerifyProof(x, wadfv.getDataForVerifier(), decryptRequests);
        Util.sop("wadr", wadr);
        assertEquals("verifyProof warnings", new ArrayList<Warning>(), wadr.getWarnings());
        checkDecryption(decryptRequests, wadr.getDecryptResponses());

        // Governance body
        if (! wadr.getDecryptResponses().isEmpty()) {
            verifyDecryption(x, wadfv.getDataForVerifier(),
                             decryptRequests, wadr.getDecryptResponses(), TestData.NONCE);
        }
    }

    public static void checkDisclosed(
      final X x,
      final DataForVerifier dfv)
        throws ApiException, IOException
    {
        final var reqD  = x.credD.getDisclosed();
        final var reqS  = x.credS.getDisclosed();
        final var rev   = dfv.getRevealedIdxsAndVals();
        final var revD  = rev.get(TestData.DL);
        final var revS  = rev.get(TestData.SUB);
        // TODOO : check indices and values
        if (reqD.isEmpty() && reqS.isEmpty()) {
            assertTrue("revealed should be empty"    ,  revD.isEmpty() &&  revS.isEmpty());
        } else {
            assertTrue("revealed should not be empty", !revD.isEmpty() || !revS.isEmpty());
        }
    }

    public static void checkDecryption(
      final Map<String, Map<String, Map<String, DecryptRequest>>> decryptRequests,
      final Map<String, Map<String, Map<String, DecryptResponse>>> decryptResponses)
        throws ApiException, IOException
    {
        assertEquals("verifyProof decryptReqs length",
                     decryptRequests.size(),
                     decryptResponses.size());

        for (Map.Entry<String, Map<String, Map<String, DecryptRequest>>> outer : decryptRequests.entrySet()) {
            final var credLabel = outer.getKey();
            for (Map.Entry<String, Map<String, DecryptRequest>> middle : outer.getValue().entrySet()) {
                final var attrIndex = middle.getKey();
                for (Map.Entry<String, DecryptRequest> inner : middle.getValue().entrySet()) {
                    final var authLabel = inner.getKey();
                    final var rsp = decryptResponses.get(credLabel).get(attrIndex).get(authLabel);
                    final var decoded = rsp.getValue();
                    Util.sop("decryption",
                             credLabel + " " + attrIndex + " " + authLabel + " " + decoded);
                    List<DataValue> vals = null;
                    if (credLabel.equals(TestData.DL)) {
                        vals = TestData.dVals();
                    } else if (credLabel.equals(TestData.SUB)) {
                        vals = TestData.sVals();
                    } else {
                        assertEquals("test misconfigured", TestData.DL, TestData.SUB);
                    }
                    assertEquals("verifyProof verifiable encryption decoding",
                                 vals.get(Integer.valueOf(attrIndex)).getDVText().getContents(),
                                 decoded);
                }
            }
        }
    }

    public static void verifyDecryption(
      final X x,
      final DataForVerifier dfv,
      final Map<String, Map<String, Map<String, DecryptRequest>>> decryptRequests,
      final Map<String, Map<String, Map<String, DecryptResponse>>> decryptResponses,
      final String nonce)
        throws ApiException, IOException
    {
        Util.banner(x, "verifyDecryption");
        final var adks  = new HashMap<String, String>();
        for (Map.Entry<String, Map<String, Map<String, DecryptRequest>>> outer : decryptRequests.entrySet()) {
            Map<String, Map<String, DecryptRequest>> middle = outer.getValue();
            for (Map.Entry<String, Map<String, DecryptRequest>> inner : middle.entrySet()) {
                Map<String, DecryptRequest> drs = inner.getValue();
                for (Map.Entry<String, DecryptRequest> dr : drs.entrySet()) {
                    adks.put(dr.getKey(), dr.getValue().getAuthorityDecryptionKey());
                }
            }
        }
        final var req = new VerifyDecryptionRequest()
            .proofReqs(x.reqs)
            .sharedParams(x.shared)
            .proof(dfv.getProof())
            .decryptionKeys(adks)
            .decryptResponses(decryptResponses)
            .nonce(nonce);
        final var w = x.api.verifyDecryption(x.zkpLib, req);
        assertEquals("verifyDecryption warnings", new ArrayList<Warning>(), w);
    }
}
