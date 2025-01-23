package com.nuvoton.otaserver.utility

import java.net.NetworkInterface

/**
 * Created by cchsu20 on 2018/6/4.
 */
class SoftAPIpaddress {
    companion object {
        private val TAG = "SoftAPIpaddress"
        fun getServerIp(): String {
            var defaultHostIp = "192.168.43.1"
            try{
                val networkInterfaces = NetworkInterface.getNetworkInterfaces()
                while (networkInterfaces.hasMoreElements()) {
                    val networkInterface = networkInterfaces.nextElement()
                    if (networkInterface.isUp && !networkInterface.isLoopback && !networkInterface.isPointToPoint) {
                        for (address in networkInterface.interfaceAddresses) {
                            val ip = address.address.toString()
                            LoggerInstance.shared.debugMessage(TAG, "ip=$ip")
                            if (ip.startsWith("/192.168")) {
                                defaultHostIp = ip
                            }
                        }
                    }
                }
            }catch (e: Exception) {
                e.printStackTrace()
            }
            return defaultHostIp.replace("/", "")
        }
    }
}