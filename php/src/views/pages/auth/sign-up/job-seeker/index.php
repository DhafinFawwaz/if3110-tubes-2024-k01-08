<?php
use src\utils\Csrf;
$csrfToken = Csrf::generateToken();
?>

<main class="main">
    <section class="signup">
        <!-- Title -->
        <h1 class="signup__title">Sign Up</h1>
        <!-- Form -->
        <form class="form" action="/auth/sign-up/job-seeker" method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
            <!-- Nama -->
            <div class="form__group">
                <label for="name" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['name'])):  ?>
                        <?= htmlspecialchars($errorFields['name'][0] ? 'form__error-message' : '') ?>
                    <?php endif; ?>
                ">
                    Name
                </label>

                <input
                    name="name"
                    type="text"
                    placeholder="Enter your name"
                    value="<?= htmlspecialchars($fields['name'] ?? '') ?>"
                    class="input" />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['name'])):  ?>
                        <?= htmlspecialchars($errorFields['name'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>

            <!-- Email -->
            <div class="form__group">
                <label for="email" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['email'])):  ?>
                        <?= htmlspecialchars($errorFields['email'][0] ? 'form__error-message' : '') ?>
                    <?php endif; ?>
                ">
                    Email
                </label>

                <input
                    name="email"
                    type="text"
                    placeholder="Enter your email"
                    value="<?= htmlspecialchars($fields['email'] ?? '') ?>"
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
                        <?= htmlspecialchars($errorFields['password'][0] ? 'form__error-message' : '') ?>
                    <?php endif; ?>
                ">
                    Password
                </label>
                <input
                    name="password"
                    type="password"
                    placeholder="Enter your password"
                    value="<?= htmlspecialchars($fields['password'] ?? '') ?>"
                    class="input" />
                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['password'])):  ?>
                        <?= htmlspecialchars($errorFields['password'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>

            <!-- submit button -->
            <button type="submit" class="button button--default-size button--default-color">
                Register Your Account
            </button>
        </form>

        <!-- Sign up -->
        <p class="signup__register-prompt">
            Already sign up your account?
            <a href="/auth/sign-in" class="anchor-link">
                Sign in
            </a>
        </p>
    </section>
</main>