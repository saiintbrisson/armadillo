package rs.luiz.hytale.offline_mode;

import com.hypixel.hytale.server.core.io.handlers.login.HandshakeHandler;
import com.hypixel.hytale.server.core.plugin.JavaPlugin;
import com.hypixel.hytale.server.core.plugin.JavaPluginInit;

public class OfflineModePlugin extends JavaPlugin {
    public OfflineModePlugin(JavaPluginInit init) {
        super(init);
    }

    @Override
    protected void setup() {
        try {
            AuthBypass.install();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
