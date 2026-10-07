# ZAP per il profilo `web`, esteso con gli add-on "potenti" del marketplace.
#
# Base pinnata per digest: un aggiornamento upstream non può rompere un rebuild.
# Gli add-on sono installati in un'unica passata headless; quelli già inclusi
# nell'immagine sono un no-op. Context di build: ./zap
FROM ghcr.io/zaproxy/zaproxy@sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef

# Installa come utente `zap` così finiscono in /home/zap/.ZAP (usati a runtime).
USER zap
RUN /zap/zap.sh -cmd -addonupdate >/dev/null 2>&1 || true \
 && /zap/zap.sh -cmd \
      -addoninstall ascanrulesAlpha \
      -addoninstall ascanrulesBeta \
      -addoninstall pscanrulesAlpha \
      -addoninstall pscanrulesBeta \
      -addoninstall accessControl \
      -addoninstall custompayloads \
      -addoninstall directorylistv2_3 \
      -addoninstall fuzzdb \
      -addoninstall grpc \
      -addoninstall httpsInfo \
      -addoninstall jython \
      -addoninstall sse \
      -addoninstall ptk
