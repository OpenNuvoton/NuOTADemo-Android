package com.nuvoton.otaoverbt.utility;


import android.content.Context;

import org.acra.config.ACRAConfiguration;
import org.acra.sender.ReportSender;
import org.acra.sender.ReportSenderFactory;

/**
 * Created by v-zhjoh on 2016/5/4.
 */
public class HockeySenderFactory implements ReportSenderFactory {
    @Override
    public ReportSender create(Context context, ACRAConfiguration config) {
        return new HockeySender();
    }
}