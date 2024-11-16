package com.tesla.easyso1;

import android.content.ComponentName;
import android.content.Intent;
import android.os.Bundle;
import android.util.Log;

import java.util.Set;

import androidx.appcompat.app.AppCompatActivity;

public class MainActivity3 extends AppCompatActivity {

    private static final String TAG = "MainActivity3";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main3);

        // 获取JS Intent传递过来的数据 https://developer.chrome.com/docs/android/intents?hl=zh-cn
        Intent intent = getIntent();
        String scheme = intent.getScheme();
        String data = intent.getDataString();
        String action = intent.getAction();
        Set<String> categories = intent.getCategories();  // JS可以传多个
        // 这里是关键 JS也可以传Extra! 官网都没细说 gpt知道
        String name = intent.getStringExtra("name");
        boolean isCheck = intent.getBooleanExtra("isCheck", false);
        ComponentName component = intent.getComponent(); // JS写错也会修改过来 这个传不传没意义 除非多个activity定义相同信息 才需要指定
        Log.d(TAG, "onCreate: scheme " + scheme);  // activity2
        // 这里可以解析
        Log.d(TAG, "onCreate: data " + data); // activity2://com.tesla.easyso1/parameter?source=aoyun&deeplinkId=topic-103666Topic_5963e4663ee748beb6a5b330b86d1b35&scene=9&url=http://101.37.16.129:5000
        Log.d(TAG, "onCreate: action " + action);  // android.intent.action.VIEW
        Log.d(TAG, "onCreate: categories " + categories); //  {android.intent.category.DEFAULT, android.intent.category.BROWSABLE}
        Log.d(TAG, "onCreate: component " + component); // ComponentInfo{com.tesla.easyso1/com.tesla.easyso1.MainActivity3}
        Log.d(TAG, "onCreate: getStringExtra.name " + name); // admin
        Log.d(TAG, "onCreate: getBooleanExtra.isCheck " + isCheck); // false
    }

    
}