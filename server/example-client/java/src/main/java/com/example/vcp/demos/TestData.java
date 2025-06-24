package com.example.vcp.demos;

// ---------------------------------------------------------------------------
import com.example.vcp.client.model.*;
// ---------------------------------------------------------------------------
import java.util.*;
import java.util.stream.*;
// ---------------------------------------------------------------------------

public class TestData
{
    public static final String AC2C_BBS              = "AC2C_BBS";
    public static final String AC2C_PS               = "AC2C_PS";
    public static final String DNC                   = "DNC";

    // --------------------------------------------------

    public static final String AUTH_LABEL            = "authorityPublic";
    public static final String NONCE                 = "nonce-from-java";

    // --------------------------------------------------

    public static final String  DL                   = "dl";
    public static final String  DL_SIGNER_PUBLIC     = "dlSignerPublic";
    public static final List<Integer> DL_REVEALED    = Arrays.asList(0);

    public static final String  DL_ACC               = "dlAcc";
    public static final Integer DL_ACC_INDEX         = 4;
    public static final String  DL_ACC_INDEX_STR     = "4";
    public static final String  DL_MPK               = "dlMpk";
    public static final String  DL_APD               = "dlAccPublicData";
    public static final String  DL_HOLDER_ID         = "dlHolderID";
    public static final Integer DL_ACC_SEQ_NUM       = 1;
    public static final String  DL_ACC_SEQ_NUM_LABEL = "DL_ACC_SEQ_NUM_LABEL";
    public static final String  DL_ACC_MEM_VALUE     = "abcdef0123456789abcdef0123456789";

    public static final String  DL_RPPK              = "dlRppk";
    public static final Integer DL_IN_RANGE_INDEX    = 1;
    public static final String  DL_RANGE_MIN         = "dlMinBDdays";
    public static final String  DL_RANGE_MAX         = "dlMaxBDdays";

    // --------------------------------------------------

    public static final String SUB                   = "sub";
    public static final String SUB_SIGNER_PUBLIC     = "subSignerPublic";
    public static final List<Integer> SUB_REVEALED   = Arrays.asList(0);

    public static final String SUB_ACC               = "subAcc";
    public static final Integer SUB_ACC_INDEX        = 1;
    public static final String SUB_ACC_INDEX_STR     = "1";
    public static final String SUB_MPK               = "subMpk";
    public static final String SUB_APD               = "subAccPublicData";
    public static final String SUB_HOLDER_ID         = "subHolderID";
    public static final Integer SUB_ACC_SEQ_NUM      = 1;
    public static final String SUB_ACC_SEQ_NUM_LABEL = "SUB_ACC_SEQ_NUM_LABEL";
    public static final String SUB_ACC_MEM_VALUE     = "aaaabcdef0123456789abcdef0123456";

    public static final String SUB_RPPK              = "subRppk";
    public static final Integer SUB_IN_RANGE_INDEX   = 2;
    public static final String SUB_RANGE_MIN         = "subMinValiddays";
    public static final String SUB_RANGE_MAX         = "subMaxValiddays";

    // ---------------------------------------------------------------------------

    public static List<DataValue> dVals() {
        final DataValue [] dvs =
            {
                  Util.mkDVText("CredentialMetadata (fromList [(\"purpose\",DVText \"DriverLicense\"),(\"version\",DVText \"1.0\")])")
                , Util.mkDVInt(37852)
                , Util.mkDVText("123-45-6789")
                , Util.mkDVInt(180)
                , Util.mkDVText(DL_ACC_MEM_VALUE)
            };
        return Arrays.asList(dvs);
    }

    public static final List<Integer> DL_BLINDED_INDICES = Arrays.asList(1,2,3,4);

    public static List<CredAttrIndexAndDataValue> dBlindedIndicesAndVals() {
        return    getBlinded(dVals(), DL_BLINDED_INDICES);
    }
    public static List<CredAttrIndexAndDataValue> dNonBlindedIndicesAndVals() {
        return getNonBlinded(dVals(), DL_BLINDED_INDICES);
    }

    public static List<ClaimType> dCTs(final String zkpLib) {
        final ClaimType [] fds =
            {     ClaimType.fromValue("CTText")
                , ClaimType.fromValue("CTInt")
                , ClaimType.fromValue("CTEncryptableText")
                , ClaimType.fromValue("CTInt")
                , ClaimType.fromValue("CTAccumulatorMember")
            };
        return Arrays.asList(fds);
    }

    // ---------------------------------------------------------------------------

    public static List<DataValue> sVals() {
        final DataValue[] svs =
            {     Util.mkDVText("CredentialMetadata (fromList [(\"purpose\",DVText \"MonthlySubscription\"),(\"version\",DVText \"1.0\")])")
                , Util.mkDVText(SUB_ACC_MEM_VALUE)
                , Util.mkDVInt(49997)
                , Util.mkDVText("123-45-6789")
            };
        return Arrays.asList(svs);
    }

    public static final List<Integer> SUB_BLINDED_INDICES = Arrays.asList(1,2,3);

    public static List<CredAttrIndexAndDataValue> sBlindedIndicesAndVals() {
        return    getBlinded(sVals(), SUB_BLINDED_INDICES);
    }
    public static List<CredAttrIndexAndDataValue> sNonBlindedIndicesAndVals() {
        return getNonBlinded(sVals(), SUB_BLINDED_INDICES);
    }

    public static List<ClaimType> sCTs(final String zkpLib) {
        final ClaimType [] fds =
            {     ClaimType.fromValue("CTText")
                , ClaimType.fromValue("CTAccumulatorMember")
                , ClaimType.fromValue("CTInt")
                , ClaimType.fromValue("CTEncryptableText")
            };
        return Arrays.asList(fds);
    }

    // ---------------------------------------------------------------------------

    public static Map<String, CredentialReqs> proofReqs() {
        final var reqs  = new HashMap<String, CredentialReqs>();
        final var credD = new CredentialReqs().signerLabel(DL_SIGNER_PUBLIC);
        final var credS = new CredentialReqs().signerLabel(SUB_SIGNER_PUBLIC);
        initCred(credD);
        initCred(credS);
        reqs.put( DL, credD);
        reqs.put(SUB, credS);
        return reqs;
    }

    // ---------------------------------------------------------------------------

    static CredentialReqs initCred(CredentialReqs x) {
        x
            .disclosed   (new ArrayList<>())
            .inAccum     (new ArrayList<>())
            .notInAccum  (new ArrayList<>())
            .inRange     (new ArrayList<>())
            .encryptedFor(new ArrayList<>())
            .equalTo     (new ArrayList<>());
        return x;
    }

    // ---------------------------------------------------------------------------

    public static Map<String, SharedParamValue> shared(final SignerPublicData dlSPub,
                                                       final SignerPublicData subSPub)
    {
        final var shared = new HashMap<String, SharedParamValue>();
        shared.put(DL_SIGNER_PUBLIC , Util.mkSPVOneText(dlSPub.toJson()));
        shared.put(SUB_SIGNER_PUBLIC, Util.mkSPVOneText(subSPub.toJson()));
        return shared;
    }

    // ------------------------------------------------------------------------------
    static List<CredAttrIndexAndDataValue> getBlinded
        (final List<DataValue> vals, final List<Integer> blinded)
    {
        return Util.enumerate(vals).stream()
            .filter(x ->   blinded.contains(x.getIndex())).collect(Collectors.toList());
    }

    static List<CredAttrIndexAndDataValue> getNonBlinded
        (final List<DataValue> vals, final List<Integer> blinded)
    {
        return Util.enumerate(vals).stream()
            .filter(x -> ! blinded.contains(x.getIndex())).collect(Collectors.toList());
    }
}
