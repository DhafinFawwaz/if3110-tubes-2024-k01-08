<?php
use src\utils\Csrf;
$csrfToken = Csrf::generateToken();
?>

<main class="main">
    <!-- Card -->
    <section class="profile">
        <!-- Back button -->
        <!-- <a href="javascript:history.back()" class="profile__back">
            <svg class="back__icon" xmlns="hsttp://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-arrow-left">
                <path d="m12 19-7-7 7-7" />
                <path d="M19 12H5" />
            </svg>

            <span>Back</span>
        </a> -->

        <!-- Title -->
        <h1 class="profile__title">
            Company Profile
        </h1>

        <!-- Form -->
        <form class="form" action="/company/profile" method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken, ENT_QUOTES, 'UTF-8'); ?>">
            <!-- Name -->
            <div class="form__group">
                <label for="name" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['name'])):  ?>
                        <?= htmlspecialchars($errorFields['name'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    Name
                </label>

                <input
                    name="name"
                    type="text"
                    placeholder="Fill in your company name"
                    value="<?= htmlspecialchars($fields['name'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                    class="input" />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['name'])):  ?>
                        <?= htmlspecialchars($errorFields['name'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>


            <!-- Location -->
            <div class="form__group">
                <label for="location" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['location'])):  ?>
                        <?= htmlspecialchars($errorFields['location'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    Location
                </label>

                <input
                    name="location"
                    type="text"
                    placeholder="Fill in your company location"
                    value="<?= htmlspecialchars($fields['location'] ?? '', ENT_QUOTES, 'UTF-8'); ?>"
                    class="input" />

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['location'])):  ?>
                        <?= htmlspecialchars($errorFields['location'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>

            <!-- About -->
            <div class="form__group">
                <label for="about" class="form__label 
                    <?php if (isset($errorFields) && isset($errorFields['about'])):  ?>
                        <?= htmlspecialchars($errorFields['about'][0] ? 'form__error-message' : '', ENT_QUOTES, 'UTF-8'); ?>
                    <?php endif; ?>
                ">
                    About
                </label>

                <textarea
                    name="about"
                    placeholder="Fill in your company about information"
                    class="textarea"
                    rows="5"><?= htmlspecialchars($fields['about'] ?? '') ?></textarea>

                <p class="form__error-message">
                    <?php if (isset($errorFields) && isset($errorFields['about'])):  ?>
                        <?= htmlspecialchars($errorFields['about'][0] ?? '') ?>
                    <?php endif; ?>
                </p>
            </div>

            <!-- Submit -->
            <button type="submit" class="button button--default-size button--default-color">
                Update
            </button>
        </form>
    </section>
</main>