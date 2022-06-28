package io.javalin.ssl.plugin;

import io.javalin.Javalin;
import io.javalin.core.plugin.Plugin;
import io.javalin.core.plugin.PluginLifecycleInit;
import lombok.RequiredArgsConstructor;
import org.jetbrains.annotations.NotNull;

@RequiredArgsConstructor
public class SSLPlugin implements Plugin {

    @Override
    public void apply(@NotNull Javalin javalin) {

    }

}

