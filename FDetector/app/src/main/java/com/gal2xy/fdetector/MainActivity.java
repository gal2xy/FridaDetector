package com.gal2xy.fdetector;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.widget.TextView;

import com.gal2xy.fdetector.databinding.ActivityMainBinding;

public class MainActivity extends AppCompatActivity {

    // Used to load the 'fdetector' library on application startup.
    static {
        System.loadLibrary("fdetector");
    }

    private ActivityMainBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        binding = ActivityMainBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // Example of a call to a native method
        TextView tv = binding.sampleText;

        initDetector();
    }

    /**
     * A native method that is implemented by the 'fdetector' native library,
     * which is packaged with this application.
     */
    public native void initDetector();
}