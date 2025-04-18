<?php
use src\utils\Csrf;
$csrfToken = Csrf::generateToken();
?>

<main class="main">
    <section class="signin">
        <!-- Title -->
        <h1 class="signin__title">Sign In</h1>
        <!-- Form -->
        <form class="form" action="/auth/sign-in" method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
            <!-- Email -->
            <div class="form__group">
                <label for="email" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['email'])):  ?>
                        <?= htmlspecialchars($errorFields['email'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    Email
                </label>

                <input
                    name="email"
                    type="text"
                    placeholder="Enter your email"
                    value="<?= htmlspecialchars($fields['email'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                    class="input" />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['email'])):  ?>
                        <?= htmlspecialchars($errorFields['email'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>

            <!-- Password -->
            <div class="form__group">
                <label for="password" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['password'])):  ?>
                        <?= htmlspecialchars($errorFields['password'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    Password
                </label>
                <input
                    name="password"
                    type="password"
                    placeholder="Enter your password"
                    value="<?= htmlspecialchars($fields['password'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                    class="input" />
                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['password'])):  ?>
                        <?= htmlspecialchars($errorFields['password'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>
            <button type="submit" class="button button--default-size button--default-color">
                Sign In
            </button>
        </form>

        <!-- Sign up -->
        <p class="signin__register-prompt">
            Don't have an account?
            <a href="/auth/sign-up" class="anchor-link">
                Sign up
            </a>
        </p>
    </section>
</main>