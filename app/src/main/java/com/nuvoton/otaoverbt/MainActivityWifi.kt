package com.nuvoton.otaoverbt

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.Intent
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Message
import android.provider.OpenableColumns
import android.util.Log
import android.view.View
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.afollestad.materialdialogs.MaterialDialog
import com.afollestad.materialdialogs.callbacks.onCancel
import com.afollestad.materialdialogs.customview.customView
import com.afollestad.materialdialogs.customview.getCustomView
import com.afollestad.materialdialogs.list.listItems
import com.nabinbhandari.android.permissions.PermissionHandler
import com.nabinbhandari.android.permissions.Permissions
import com.nuvoton.otaserver.ServerCallBack
import com.nuvoton.otaserver.setServerCallBackListener
import com.nuvoton.otaserver.utility.LocalSetting
import com.nuvoton.otaserver.utility.SoftAPIpaddress
import com.snatik.storage.Storage
import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.text.DecimalFormat
import kotlin.concurrent.thread

class MainActivityWifi : AppCompatActivity(), ServerCallBack {
    /**
     * Kotlin will not create handler leak as Java does, so this is just suppressed
     * Ref: https://stackoverflow.com/a/48099735/6143603
     */

    val messageHandler = @SuppressLint("HandlerLeak")
    object : Handler() {
        override fun handleMessage(msg: Message) {
            val list = msg?.data?.getStringArrayList("list")
            val stateString = list?.get(0)
            val responseStatus = list?.get(1)
            val progress = list?.get(2)
            val progressLimit = list?.get(3)
            val state = com.nuvoton.otaserver.OTAWifiState.valueOf(stateString ?: "Error")
            val stateChange = currentState != state
            currentState = state
            if (responseStatus != null && progress != null && progressLimit != null)
                updateProgress(stateChange, state, responseStatus, progress, progressLimit)
        }
    }

    @SuppressLint("StringFormatMatches")
    fun updateProgress(
        stateChange: Boolean,
        state: com.nuvoton.otaserver.OTAWifiState,
        responseStatus: String,
        progress: String,
        progressLimit: String
    ) {
        val stateString = when (state) {
            com.nuvoton.otaserver.OTAWifiState.Idle -> getString(R.string.ota_wifi_state_idle)
            com.nuvoton.otaserver.OTAWifiState.Connect -> getString(R.string.ota_wifi_state_connected)
            com.nuvoton.otaserver.OTAWifiState.Req_Ecdh_Pub0 -> getString(R.string.ota_wifi_state_ecdh_pub0)
            com.nuvoton.otaserver.OTAWifiState.Req_Ecdh_Pub1 -> getString(R.string.ota_wifi_state_ecdh_pub1)
            com.nuvoton.otaserver.OTAWifiState.Req_Ecdh_Get_Pub0 -> getString(R.string.ota_wifi_state_get_ecdh_pub0)
            com.nuvoton.otaserver.OTAWifiState.Req_Ecdh_Get_Pub1 -> getString(R.string.ota_wifi_state_get_ecdh_pub1)
            com.nuvoton.otaserver.OTAWifiState.Req_Ecdh_Rand_Pub0 -> getString(R.string.ota_wifi_state_rand_ecdh_pub0)
            com.nuvoton.otaserver.OTAWifiState.Req_Ecdh_Rand_Pub1 -> getString(R.string.ota_wifi_state_rand_ecdh_pub1)
            com.nuvoton.otaserver.OTAWifiState.Req_Ecdh_Get_Rand_Pub0 -> getString(R.string.ota_wifi_state_get_ecdh_pub0)
            com.nuvoton.otaserver.OTAWifiState.Req_Ecdh_Get_Rand_Pub1 -> getString(R.string.ota_wifi_state_get_ecdh_pub1)
            com.nuvoton.otaserver.OTAWifiState.Req_Auth_Key_Sys -> getString(R.string.ota_wifi_state_auth_sys)
            com.nuvoton.otaserver.OTAWifiState.Req_Set_Mass_Write_Sys -> getString(R.string.ota_wifi_state_set_write_sys)
            com.nuvoton.otaserver.OTAWifiState.Req_Mass_Write_Sys -> getString(R.string.ota_wifi_state_write_sys)
            com.nuvoton.otaserver.OTAWifiState.Req_Auth_Key_App -> getString(R.string.ota_wifi_state_auth_app)
            com.nuvoton.otaserver.OTAWifiState.Req_Set_Mass_Write_App -> getString(R.string.ota_wifi_state_set_write_app)
            com.nuvoton.otaserver.OTAWifiState.Req_Mass_Write_App -> getString(R.string.ota_wifi_state_write_app)
            com.nuvoton.otaserver.OTAWifiState.Disconnect -> getString(R.string.ota_wifi_state_disconnect)
            com.nuvoton.otaserver.OTAWifiState.Error -> getString(R.string.ota_wifi_state_error)
        }
//        val percent = "${progress.toFloat() / progressLimit.toFloat()}"
        runOnUiThread {
            when (state) {
                com.nuvoton.otaserver.OTAWifiState.Disconnect -> {
                    updateDialog.title(R.string.title_ota_done)
                    updateDialog.message(R.string.content_ota_complete)
                    updateDialog.negativeButton(R.string.general_okay)
                    buttonStartOTA.text = getString(R.string.title_open_server)
                }

                else -> when (responseStatus.toInt()) {
                    com.nuvoton.otaserver.OTAConstants.STS_REBOOT -> {
                        updateDialog.title(R.string.title_client_reboot)
                        updateDialog.message(R.string.content_client_reboot)
                        updateDialog.negativeButton(R.string.general_okay)
                    }

                    com.nuvoton.otaserver.OTAConstants.ERR_CMD_CHECKSUM -> {
                        updateDialog.title(R.string.title_checksum_error)
                        updateDialog.message(R.string.content_checksum_error)
                        updateDialog.negativeButton(R.string.general_okay)
                    }

                    com.nuvoton.otaserver.OTAConstants.ERR_OLD_FW_VER -> {
                        updateDialog.title(R.string.title_firmware_older)
                        updateDialog.message(R.string.content_client_latest)
                        updateDialog.negativeButton(R.string.general_okay)
                    }

                    else -> {
                        if (stateChange) {
                            updateDialog.setTitle(stateString)
                            progressBar?.max = progressLimit.toInt()
//                        updateDialog.maxProgress = progressLimit.toInt()
                        } else {
                            progressBar?.progress = progress.toInt()
                            progressBar?.progress = progress.toInt()
                            val percent =
                                (progress.toFloat() / progressLimit.toFloat() * 100).toInt()  // 將浮點數轉換為整數
                            textviewPercent?.text =
                                resources.getString(R.string.string_percent, percent)
                            textviewProgress?.text = resources.getString(R.string.string_progress,progress.toInt(),progressLimit)

                        }
                    }
                }
            }
        }
    }

    private val BUFFER_SIZE = 256
    private val CRC_SIZE = 2
    lateinit var editInputPatter: EditText
    lateinit var editSys: EditText
    lateinit var editApp: EditText
    lateinit var editLicense: EditText
    lateinit var buttonStartOTA: Button
    lateinit var buttonSysFW: Button
    lateinit var buttonAppFW: Button
    lateinit var buttonLicense: Button
    lateinit var storage: Storage
    lateinit var textviewServerIp: TextView
    lateinit var versionName: TextView
//    private var folderPath = ""
    lateinit var updateDialog: MaterialDialog
    private var currentState: com.nuvoton.otaserver.OTAWifiState? = null
    private var progressBar: ProgressBar? = null
    private var textviewPercent: TextView? = null
    private var textviewProgress: TextView? = null
    private val PICK_SYSFW_FILE_REQUEST_CODE = 999
    private val PICK_APPFW_FILE_REQUEST_CODE = 888
    private val PICK_LICENSE_FILE_REQUEST_CODE = 777

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main_wifi)

        //TODO("setServerCallBackListener")
        setServerCallBackListener(this)

        buttonSysFW = findViewById(R.id.buttonSysFW)
        buttonSysFW.setOnClickListener(onSelect_SYSFW_File)

        buttonAppFW = findViewById(R.id.buttonAppFW)
        buttonAppFW.setOnClickListener(onSelect_APPFW_File)

        buttonLicense = findViewById(R.id.buttonLicense)
        buttonLicense.setOnClickListener(onSelect_LICENSE_File)

        // 检查并请求读取文件的权限
        if (checkPermission()) {
//            startFilePicker(requestCode)
        } else {
//            requestPermission()
        }

        storage = Storage(applicationContext)

        setViews()
//        EncryptHelper.shared.testAES256()
    }

    private fun checkPermission(): Boolean {
        return ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.READ_EXTERNAL_STORAGE
        ) == PackageManager.PERMISSION_GRANTED
    }

    private fun requestPermission(requestCode: Int) {
        ActivityCompat.requestPermissions(
            this,
            arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
            requestCode
        )
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
            startFilePicker(requestCode)
        } else {
            Log.d(this.javaClass.name, "权限被拒绝，无法读取文件")
        }
    }

    private fun startFilePicker(requestCode: Int) {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT)
        intent.addCategory(Intent.CATEGORY_OPENABLE)
        intent.type = "*/*"  // 任意类型的文件

        startActivityForResult(intent, requestCode)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if ( resultCode == RESULT_OK) {
            data?.data?.let { uri ->
                readSelectedFile(uri,requestCode)
            }
        } else {
            Log.d(this.javaClass.name, "文件选择取消")
        }
    }

    private fun readSelectedFile(uri: Uri, requestCode: Int) {
        try {
            val inputStream: InputStream? = contentResolver.openInputStream(uri)

            when (requestCode){

                PICK_SYSFW_FILE_REQUEST_CODE -> {

                    val fileName = getFileName(uri)
                    // 檢查副檔名是否為 .bin
                    if (!fileName.endsWith(".bin", ignoreCase = true)) {
                        Toast.makeText(this, "Incorrect file type selected.", Toast.LENGTH_SHORT).show()
                        return
                    }

                    // 读取文件内容为 ByteArray
                    val byteArray = inputStream?.readBytes()
                    inputStream?.close()
                    val data = byteArray
                    Log.d(this.javaClass.name, "成功读取文件数据:\n$data")


                    com.nuvoton.otaserver.OTAServer.shared.sysFw = data
                    runOnUiThread {
                        editSys.setText(fileName)
                    }
                }
                PICK_APPFW_FILE_REQUEST_CODE -> {

                    val fileName = getFileName(uri)
                    // 檢查副檔名是否為 .bin
                    if (!fileName.endsWith(".bin", ignoreCase  = true)){
                        Toast.makeText(this, "Incorrect file type selected.", Toast.LENGTH_SHORT).show()
                        return
                    }

                    // 读取文件内容为 ByteArray
                    val byteArray = inputStream?.readBytes()
                    inputStream?.close()
                    val data = byteArray
                    Log.d(this.javaClass.name, "成功读取文件数据:\n$data")

                    com.nuvoton.otaserver.OTAServer.shared.appFw = data

                    runOnUiThread {
                        editApp.setText(fileName)
                    }
                }
                PICK_LICENSE_FILE_REQUEST_CODE -> {

                    val fileName = getFileName(uri)
                    // 檢查副檔名是否為 .bin
                    if (!fileName.endsWith(".txt", ignoreCase = true)) {
                        Toast.makeText(this, "Incorrect file type selected.", Toast.LENGTH_SHORT).show()
                        return
                    }

                    val reader = BufferedReader(InputStreamReader(inputStream))
                    val stringBuilder = StringBuilder()
                    var line: String?

                    while (reader.readLine().also { line = it } != null) {
                    stringBuilder.append(line).append("\n")
                    }
                    inputStream?.close()
                    val data =  stringBuilder.toString()
                    com.nuvoton.otaserver.OTAServer.shared.license = data

                    runOnUiThread {
                        editLicense.setText(fileName)
                    }
                }
            }


        } catch (e: Exception) {
            Log.d(this.javaClass.name, "读取文件失败: ${e.message}")
        }
    }

    private fun getFileName(uri: Uri): String {
        var result = ""
        try {
            val cursor = contentResolver.query(uri, null, null, null, null)
            cursor?.use {
                if (it.moveToFirst()) {
                    val displayNameIndex = it.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                    if (displayNameIndex != -1) {
                        val displayName = it.getString(displayNameIndex)
                        result = displayName
                    } else {
                        // Handle the case where DISPLAY_NAME column is not found
                        // You can provide a default name or take appropriate action
                    }
                }
            }
        } catch (e: Exception) {
            // Handle exceptions
            e.printStackTrace()
        }
        return result
    }


    //選擇檔案SYSFW
    private val onSelect_SYSFW_File = View.OnClickListener { button ->
        startFilePicker(PICK_SYSFW_FILE_REQUEST_CODE)
    }
    //選擇檔案APPFW
    private val onSelect_APPFW_File = View.OnClickListener { button ->
        startFilePicker(PICK_APPFW_FILE_REQUEST_CODE)
    }
    //選擇檔案LICENSE
    private val onSelect_LICENSE_File = View.OnClickListener { button ->
        startFilePicker(PICK_LICENSE_FILE_REQUEST_CODE)
    }

    private fun setViews() {
        textviewServerIp = findViewById(R.id.textview_server_ip)
        textviewServerIp.text = SoftAPIpaddress.getServerIp()
        versionName  = findViewById(R.id.versionName)
        try {
            val pInfo: PackageInfo = this.getPackageManager().getPackageInfo(this.getPackageName(), 0)
            val version: String = pInfo.versionName
            versionName.text = "version:"+version
        } catch (e: PackageManager.NameNotFoundException) {
            e.printStackTrace()
        }

        editSys = findViewById(R.id.editSysFW)
        editApp = findViewById(R.id.editAppFW)
        editLicense = findViewById(R.id.editLicense)

        buttonStartOTA = findViewById(R.id.buttonStartOTA)
        buttonStartOTA.setOnClickListener { view -> //按鈕點擊

            if(com.nuvoton.otaserver.OTAServer.shared.sysFw?.isNotEmpty() != true
                ||com.nuvoton.otaserver.OTAServer.shared.appFw?.isNotEmpty()!= true
                ||com.nuvoton.otaserver.OTAServer.shared.license?.isNotEmpty()!= true){

                updateDialog = MaterialDialog(this)
                    .title(R.string.file_selection_error)
                    .message(R.string.Please_check_correctly)
                    .positiveButton(R.string.okay) { dialog ->
                        // 在此處處理確定按鈕的相應操作
                        dialog.dismiss()
                    }
                    .show {
                        onCancel {
                            com.nuvoton.otaserver.OTAServer.shared.closeServer()
//                                showToast(getString(R.string.toast_ota_stopped))
                        }
                    }

                return@setOnClickListener
            }

            val button = view as Button
            button.text = getString(R.string.button_ota_start)
            if (com.nuvoton.otaserver.OTAServer.shared.isUpdating) com.nuvoton.otaserver.OTAServer.shared.closeServer() else {

                //這邊開啟服務
                com.nuvoton.otaserver.OTAServer.shared.messageHandler = messageHandler
//                com.nuvoton.otaserver.OTAServer.shared.openServer(storage)
                this.openServer(storage)

                updateDialog = MaterialDialog(this)
                        .title(R.string.title_open_server)
                        .message(R.string.content_ota_wait_client)
                        .show {
                            customView(R.layout.progressbar)
                            onCancel {
                                com.nuvoton.otaserver.OTAServer.shared.closeServer()
//                                showToast(getString(R.string.toast_ota_stopped))
                            }
                        }
                progressBar = updateDialog.getCustomView().findViewById(R.id.progress_bar)
                textviewPercent = updateDialog.getCustomView().findViewById(R.id.textview_percentage)
                textviewProgress = updateDialog.getCustomView().findViewById(R.id.textview_progress)
            }
        }
    }

//    private val onSelectFile = View.OnClickListener { button ->
//        val files = storage.getNestedFiles(folderPath)
//        val list: ArrayList<String> = ArrayList()
//        for (file in files) {
//            list.add(file.name)
//        }
//        MaterialDialog(this)
//                .onCancel {
//                    val notFound = getString(R.string.string_not_found)
//                    when {
//                        button.id == R.id.buttonSysFW -> editSys.setText(notFound)
//                        button.id == R.id.buttonAppFW -> editApp.setText(notFound)
//                        else -> editLicense.setText(notFound)
//                    }
//                }
//                .title(R.string.title_select_firmware).listItems(items = list) { dialog, position, text ->
//                    val file = files[position]
//                    when {
//                        button.id == R.id.buttonSysFW -> editSys.setText(file.name)
//                        button.id == R.id.buttonAppFW -> editApp.setText(file.name)
//                        else -> editLicense.setText(file.name)
//                    }
//                }.show {
//                    negativeButton(R.string.general_cancel) {
//                        val notFound = getString(R.string.string_not_found)
//                        when {
//                            button.id == R.id.buttonSysFW -> editSys.setText(notFound)
//                            button.id == R.id.buttonAppFW -> editApp.setText(notFound)
//                            else -> editLicense.setText(notFound)
//                        }
//                    }
//                    positiveButton(R.string.general_okay) {  }
//                }
//    }

    //建立連線
    private var serverSocket: ServerSocket? = null
    private var socketAccept : Socket? = null
    private val PORT_NUM = 1111
    private val PACKET_LENGTH = 64
    fun openServer(storage: Storage) {
        thread {
            try {
                if (serverSocket != null && !serverSocket!!.isClosed) {
//                    serverSocket?.close()
//                    serverSocket = null
                } else {
                    serverSocket = ServerSocket()
                    serverSocket?.reuseAddress = true
                    serverSocket?.bind(InetSocketAddress(PORT_NUM))
                }

                thread {
                    Log.i("serverSocket", "serverSocket is accept")
                    socketAccept = serverSocket!!.accept()
                    com.nuvoton.otaserver.OTAServer.shared.openServer(storage)
//                    val clientHandler = ClientHandler(serverSocket!!.accept())
//                    clientHandler.socketInterface = object : ClientHandler.SocketInterface {
//                        override fun closeSocket() {
//                            serverSocket?.close()
//                            isUpdating = false
//                        }
//                    }
                }
            }catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    override fun toWrite(byteArray: ByteArray) {
        //TODO("write this Data to MCU")

        if(socketAccept == null){
            return
        }
        socketAccept!!.getOutputStream().write(byteArray)
    }

    override fun getConnectBuffer(): ByteArray {
        //TODO("Read MCU Data And return")
        var buffer = ByteArray(11)
        if(socketAccept == null){
            return buffer
        }
        socketAccept!!.getInputStream().read(buffer, 0, 11)
        return buffer
    }

    override fun getBuffer(): ByteArray {
        //TODO("Read MCU Data And return")

        var buffer = ByteArray(PACKET_LENGTH)
        if(socketAccept == null){
            return buffer
        }
        socketAccept!!.getInputStream().read(buffer, 0, PACKET_LENGTH)
        return buffer
    }


}
