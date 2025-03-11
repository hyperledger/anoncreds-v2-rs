package com.example.vcp.demos;

// ------------------------------------------------------------------------------
import com.example.vcp.client.model.*;
// ------------------------------------------------------------------------------

public class Util
{
    // ------------------------------------------------------------------------------

    public static String quote(final String in) {
        return "\"" + in +  "\"";
    }

    // ------------------------------------------------------------------------------

    public static void banner(final String m, final String z) {
        System.out.println();
        System.out.println("------------------------- " + m + " " + z + " -------------------------");
    }

    public static void sop(final String m, final Object o) {
        // banner(m, "");
        // System.out.println(o);
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

}
