<template>
  <section class="csrf-page csrf-guide-page">
    <div class="csrf-page-heading">
      <div>
        <span class="csrf-eyebrow">OPERATOR PLAYBOOK</span>
        <h2>Manual review guide</h2>
        <p>
          Use passive evidence to plan a controlled test, never as a
          vulnerability verdict.
        </p>
      </div>
    </div>

    <div class="csrf-guide-steps">
      <article>
        <span>01</span>
        <div>
          <h3>Establish scope and impact</h3>
          <p>
            Use only authorized targets and a dedicated test account. Understand
            password, payment, permission, deletion, and session side effects
            before replaying anything.
          </p>
        </div>
      </article>
      <article>
        <span>02</span>
        <div>
          <h3>Read passive barriers</h3>
          <p>
            Review ambient authentication, token placement, request
            forgeability, Origin/Referer, Fetch Metadata, CORS, and observed
            SameSite evidence. None proves server enforcement alone.
          </p>
        </div>
      </article>
      <article>
        <span>03</span>
        <div>
          <h3>Create inert variants</h3>
          <p>
            Inspect the control, removed-token, invalid-token, and cross-site
            variants in Replay. The plugin creates sessions but never presses
            Send.
          </p>
        </div>
      </article>
      <article>
        <span>04</span>
        <div>
          <h3>Verify real state</h3>
          <p>
            Record whether each request was accepted, then independently verify
            account or application state. Status codes and similar bodies are
            insufficient.
          </p>
        </div>
      </article>
      <article>
        <span>05</span>
        <div>
          <h3>Make a defensible decision</h3>
          <p>
            Save the verification matrix and reviewer note. Publish a Caido
            Finding only after manual confirmation.
          </p>
        </div>
      </article>
    </div>

    <div class="csrf-guide-grid">
      <article class="csrf-panel">
        <span class="csrf-eyebrow">PRIORITY MODEL</span>
        <h3>What the queue means</h3>
        <p>
          <strong>P1:</strong> likely ambient authentication,
          sensitive/browser-forgeable action, and no identified token or strong
          observed cookie barrier.
        </p>
        <p>
          <strong>P2:</strong> missing, weak, or unknown token evidence with a
          browser or protocol barrier that still needs testing.
        </p>
        <p>
          <strong>P3:</strong> authentication or state-change evidence remains
          uncertain.
        </p>
        <p>
          <strong>Protection observed:</strong> a token-like signal exists;
          server validation remains unproven.
        </p>
      </article>
      <article class="csrf-panel">
        <span class="csrf-eyebrow">IMPORTANT LIMITS</span>
        <h3>What passive analysis cannot prove</h3>
        <p>
          Origin, Referer, Fetch Metadata, CORS, and SameSite are
          observations—not proof of validation.
        </p>
        <p>
          WebSocket review covers the upgrade handshake for CSWSH, not
          application messages.
        </p>
        <p>
          Opaque, protobuf, oversized, and gRPC bodies are classified as unknown
          rather than guessed.
        </p>
        <p>
          Offline PoCs are limited to representable GET and URL-encoded POST
          forms.
        </p>
      </article>
    </div>
  </section>
</template>
