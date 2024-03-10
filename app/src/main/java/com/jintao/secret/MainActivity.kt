package com.jintao.secret

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.util.Log
import com.jintao.secret.databinding.ActivityMainBinding

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

//        val sample = "123456"
        val sample = "Eq3R5s9z7HZOES1+Ht8fWw=="
        val encrypyUtils = EncrypyUtils()
        val initstatus = encrypyUtils.init()

        if (initstatus) {//初始化成功
//            val encode = encrypyUtils.encode(sample)
            val decode = encrypyUtils.decode(sample)
            Log.e("AAAAAA",decode)
        }else {
            Log.e("AAAAAA","初始化失败")
        }
    }
}