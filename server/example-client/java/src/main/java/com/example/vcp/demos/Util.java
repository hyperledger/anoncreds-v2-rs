package com.example.vcp.demos;

// ------------------------------------------------------------------------------
import com.example.vcp.client.model.*;
// ------------------------------------------------------------------------------
import java.util.ArrayList;
import java.util.List;
// ------------------------------------------------------------------------------

public class Util
{
    // ------------------------------------------------------------------------------

    public static String quote(final String in) {
        return "\"" + in +  "\"";
    }

    // ------------------------------------------------------------------------------

    public static void banner(final X x, final String m) {
        bannerAux(m + " " + zpkLibAndSigTypeString(x));
    }

    static String zpkLibAndSigTypeString(final X x) {
        return  x.zkpLib + " " + x.sigType.toString();
    }

    static void bannerAux(final String m) {
        System.out.println();
        System.out.println("------------------------- " + m + " -------------------------");
    }

    static final boolean DO_PRINT = false;

    public static void sop(final String m, final Object o) {
        if (DO_PRINT) {
            bannerAux(m);
            System.out.println(o);
        }
    }

    // ---------------------------------------------------------------------------

    public static SharedParamValue mkSPVOneText(final String x) {
        return new SharedParamValue
            (new SPVOne()
             .contents(mkDVText(x))
             .tag(SPVOne.TagEnum.SPV_ONE));
    }

    public static SharedParamValue mkSPVOneLong(final Integer x) {
        return new SharedParamValue
            (new SPVOne()
             .contents(mkDVInt(x))
             .tag(SPVOne.TagEnum.SPV_ONE));
    }

    public static DataValue mkDVInt(final Integer x) {
        return new DataValue
            (new DVInt()
             .contents(x)
             .tag(DVInt.TagEnum.DV_INT));
    }

    public static DataValue mkDVText(final String x) {
        return new DataValue
            (new DVText()
             .contents(x)
             .tag(DVText.TagEnum.DV_TEXT));
    }

    // ------------------------------------------------------------------------------

    public static List<CredAttrIndexAndDataValue> enumerate(final List<DataValue> l)
    {
        List<CredAttrIndexAndDataValue> result = new ArrayList<>(l.size());
        for (int i = 0; i < l.size(); i++) {
            result.add(new CredAttrIndexAndDataValue().index(i).value(l.get(i)));
        }
        return result;
    }
}
