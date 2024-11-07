#!/bin/bash

# Sets up a Django-Nuxt project.

if ! [ $# -eq 1 ] || [ $# -eq 2 ]; then
    echo "Mandatory first argument: project name
Optional second argument: remote git repository link"
    exit 1
fi
project_name="$1"
git_repo="$2"

if [ -d "$project_name" ]; then
    echo "Directory '$project_name' already exists."
    read -p "Do you want to delete it? (y/N): " del_answer
    del_answer=${del_answer:-n}
    if [[ "$del_answer" == "y" || "$del_answer" == "Y" ]]; then
        rm -rf "$project_name"
    else
        exit 0
    fi
fi

sudo apt update && sudo apt install -y git python3 python3-django nodejs

git_name=$(git config --global user.name)
git_email=$(git config --global user.email)
if [ -z "$user_name" ]; then
    echo "Git user.name is not set. Please enter your name:"
    read -r user_name
    git config --global user.name "$user_name"
fi
if [ -z "$user_email" ]; then
    echo "Git user.email is not set. Please enter your email:"
    read -r user_email
    git config --global user.email "$user_email"
fi

mkdir $project_name && cd $project_name
curl -o LICENSE.txt https://www.gnu.org/licenses/old-licenses/gpl-2.0.txt
touch .gitignore README.md backend.log frontend.log dev_project.sh housekeep_project.sh requirements.txt

echo '# Local env files
*.env
*.env.production

# Python virtual environment
venv/

# Database files
*.sqlite
*.sqlite3

# Log files
*.log' >> .gitignore

echo "# $project_name 
Project generated from a lichenaut script

See \`housekeep_project.sh\` to blindly maintain your project.

See \`dev_project.sh\` to locally deploy your project.

User accounts are set up in a way where only an admin can register new accounts.

Sitemap generator: https://www.xml-sitemaps.com/" >> README.md

echo '#!/bin/bash

filter_numbers() {
    while read line; do
        if [[ "$line" =~ ^[0-9]+$ ]]; then
            echo "$line"
        fi
    done
}

cleanup() {
    kill $frontend_pid
    kill $backend_pid
    deactivate
    exit 0
}

trap cleanup SIGINT

. $(pwd)/venv/bin/activate
cd backend && python3 manage.py runserver &>> ../backend.log &
backend_pid=$(echo $! | filter_numbers)
cd frontend && pnpm dev -o &>> ../frontend.log &
frontend_pid=$(echo $! | filter_numbers)

echo "Starting servers! Visit http://localhost:8000/ and http://localhost:3000/ in-browser."
echo "Press CONTROL+C to quit."

while true; do
    sleep 10
done' >> dev_project.sh

chmod +x dev_project.sh

echo '#!/bin/bash

# Please know that this script updates packages blindly and deletes backend/db.sqlite3.

rm -rf backend/db.sqlite3
. $(pwd)/venv/bin/activate
pip freeze > requirements.txt
pip install -r requirements.txt --upgrade
cd backend && python3 manage.py makemigrations && python3 manage.py migrate && cd ..
black $(pwd)
deactivate

cd frontend && pnpm install && pnpm prettier --write . && cd ..' >> housekeep_project.sh

chmod +x housekeep_project.sh

read -p "Would you like to set up basic JWT token authentication? (Y/n): " jwt_answer
jwt_answer=${jwt_answer:-y}
read -p "Would you like to include basic e-mail server configuration? (Y/n): " mail_answer
mail_answer=${mail_answer:-y}
django-admin startproject backend && cd backend && python3 manage.py startapp api && touch .gitignore

if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	mkdir backend/management backend/management/commands && touch backend/management/__init__.py backend/management/commands/__init__.py backend/management/commands/create_groups.py
fi

echo 'api/migrations/
api/__pycache__/
backend/__pycache__/
backend/management/__pycache__/
backend/management/commands/__pycache__/' >> .gitignore

if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo "from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group

class Command(BaseCommand):
    help = 'Create User and Administrator groups'

    def handle(self, *args, **kwargs):
        groups = ['User', 'Administrator']

        for group_name in groups:
            group, created = Group.objects.get_or_create(name=group_name)" >> backend/management/commands/create_groups.py
fi

cd api && rm -rf models.py views.py && touch models.py serializers.py urls.py views.py

echo 'from django.db import models' >> models.py
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo 'from django.contrib.auth.models import User, Group' >> models.py
fi

if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo 'from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.conf import settings
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from .models import User, Group

class UserSerializer(serializers.ModelSerializer):
    firstName = serializers.CharField(source="first_name", required=True)
    lastName = serializers.CharField(source="last_name", required=True)
    role = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ["id", "firstName", "lastName", "email", "password", "role"]
        extra_kwargs = {"password": {"write_only": True}}

    def create(self, validated_data):
        user = User.objects.create_user(
            username=validated_data.get("email"),
            first_name=validated_data.get("first_name"),
            last_name=validated_data.get("last_name"),
            email=validated_data.get("email"),
            password=validated_data.get("password"),
        )

        user_group, created = Group.objects.get_or_create(name="User")
        user.groups.add(user_group)' >> serializers.py
fi
if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]] && [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
    echo '        self._send_account_creation_email(user)
        return user

    def _send_account_creation_email(self, user):
        token_generator = PasswordResetTokenGenerator()
        uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
        token = token_generator.make_token(user)
        reset_link = f"http://localhost:3000/new-password/{uidb64}/{token}"

        subject = "Account Creation and Password Change"
        html_message = f"""
        <html>
            <body>
                <p>Dear {user.first_name},</p>
                <p>An account was created with this email address.</p>
                <p>If you did not initiate this, please change your password using the link below:</p>
                <p><a href="{reset_link}">Reset Password</a></p>
                <p>If you did not request this, please disregard this message.</p>
                <p>Best regards,</p>
            </body>
        </html>
        """
        plain_message = (
            f"Dear {user.first_name},\n"
            "An account was created with this email address.\n"
            f"If you did not initiate this, please change your password using the link below:\n{reset_link}\n"
            "If you did not request this, please disregard this message.\nBest regards,"
        )

        send_mail(
            subject,
            message=plain_message,
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email],
            fail_silently=False,
            html_message=html_message,
        )' >> serializers.py
elif [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
    echo '        return user' >> serializers.py
fi
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
    echo '
    def get_role(self, obj):
        return [group.name for group in obj.groups.all()]


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)
        token["roles"] = [group.name for group in user.groups.all()]
        return token' >> serializers.py
fi
if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]] && [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo 'class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(required=True)

    def validate_email(self, value):
        if not User.objects.filter(email=value).exists():
            raise serializers.ValidationError("User with this email does not exist.")
        return value


class PasswordChangeSerializer(serializers.Serializer):
    new_password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = self.context.get("user")
        user.set_password(data["new_password"])
        user.save()
        return data' >> serializers.py
fi

echo 'from django.urls import path' >> urls.py
if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]] && [[ "$jwt_answer" == "y" || "$jwt     _answer" == "Y" ]]; then
	echo 'from api.views import NewPasswordView, PasswordResetRequest' >> urls.py
fi
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo 'from api.views import (
    CreateUserView,
    DeleteUserView,
    ListUserView,
    UpdateUserRoleView,
    CustomTokenObtainPairView,
)
from rest_framework_simplejwt.views import TokenRefreshView' >> urls.py
fi
echo '
urlpatterns = [' >> urls.py
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo '    path("token/", CustomTokenObtainPairView.as_view(), name="get_token"),
    path("token/refresh/", TokenRefreshView.as_view(), name="refresh_token"),
    path("user/register/", CreateUserView.as_view(), name="register_user"),
    path("user/delete/<int:pk>/", DeleteUserView.as_view(), name="delete_user"),
    path("users/", ListUserView.as_view(), name="list_users"),
    path(
        "user/update/<int:pk>/",
        UpdateUserRoleView.as_view(),
        name="update_user_role",
    ),' >> urls.py
fi
if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]] && [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
    echo '    path(
        "change-password/", PasswordResetRequest.as_view(), name="change_password"
    ),
    path(
        "new-password/<str:uidb64>/<str:token>/",
        NewPasswordView.as_view(),
        name="new_password",
    ),' >> urls.py
fi
echo ']' >> urls.py

echo 'from django.shortcuts import render' >> views.py
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo 'from django.contrib.auth.models import User, Group
from rest_framework import generics, status
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from django.core.mail import send_mail
from django.conf import settings
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .serializers import UserSerializer, CustomTokenObtainPairSerializer' >> views.py
fi
if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]] && [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo 'from .serializers import PasswordResetRequestSerializer' >> views.py
fi
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo "class CreateUserView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        user_group = Group.objects.get(name=\"User\")
        user.groups.add(user_group)
        user.save()


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer
    permission_classes = [AllowAny]


class DeleteUserView(generics.DestroyAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]


class ListUserView(generics.ListAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]


class UpdateUserRoleView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdminUser]

    def patch(self, request, *args, **kwargs):
        user = self.get_object()
        role = request.data.get(\"role\")

        valid_roles = [\"Administrator\", \"User\"]
        if role not in valid_roles:
            return Response(
                {\"message\": f\"Role must be one of: {', '.join(valid_roles)}.\"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user.groups.clear()
        group, created = Group.objects.get_or_create(name=role)
        user.groups.add(group)
        user.save()

        return Response(
            {\"message\": f\"User role updated to {role}.\"}, status=status.HTTP_200_OK
        )" >> views.py
fi
if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]] && [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo '
class PasswordResetRequest(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data.get("email")

            try:
                user = User.objects.get(email=email)
                token_generator = PasswordResetTokenGenerator()
                uidb64 = urlsafe_base64_encode(force_bytes(user.pk))
                token = token_generator.make_token(user)
                reset_link = f"http://localhost:3000/new-password/{uidb64}/{token}"

                html_message = f"""
                <html>
                    <body>
                        <p>Click the link below to reset your password:</p>
                        <a href="{reset_link}">Reset Password</a>
                    </body>
                </html>
                """
                send_mail(
                    "Password Reset Request",
                    f"Click the link below to reset your password:\n{reset_link}",
                    settings.EMAIL_HOST_USER,
                    [email],
                    fail_silently=False,
                    html_message=html_message,
                )

                return Response(
                    {"message": "Password reset link sent!"}, status=status.HTTP_200_OK
                )

            except User.DoesNotExist:
                return Response(
                    {"message": "User with this email does not exist."},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class NewPasswordView(APIView):
    permission_classes = [AllowAny]

    def post(self, request, uidb64, token):
        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            token_generator = PasswordResetTokenGenerator()

            if token_generator.check_token(user, token):
                new_password = request.data.get("new_password")
                user.set_password(new_password)
                user.save()
                return Response(
                    {"message": "Password has been updated."}, status=status.HTTP_200_OK
                )

            return Response(
                {"message": "Token is invalid or expired"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response(
                {"message": "Invalid token or user ID"},
                status=status.HTTP_400_BAD_REQUEST,
            )' >> views.py
fi

cd .. && cd backend && rm -rf urls.py && touch urls.py
echo 'from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path("admin/", admin.site.urls),' >> urls.py
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
    echo '    path("api/", include("api.urls"), name="api"),
    path("api-auth/", include("rest_framework.urls"), name="api-auth"),' >> urls.py
fi
echo ']' >> urls.py

cd ../..

echo "asgiref
Django
django-cors-headers
djangorestframework
pytz
sqlparse
psycopg2-binary
python-dotenv
black
" >> requirements.txt
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo "
	djangorestframework-simplejwt
	PyJWT
	" >> requirements.txt
fi

python3 -m venv venv && . $(pwd)/venv/bin/activate && pip install -r requirements.txt && deactivate
SETTINGS_PY="$(pwd)/backend/backend/settings.py"

sed -i "/^from pathlib import Path$/a\\
from datetime import timedelta\\
from dotenv import load_dotenv\\
import os\\
\\
load_dotenv()" "$SETTINGS_PY"
sed -i "/^# SECURITY WARNING: keep the secret key used in production secret!/ s/SECURITY/TODO: SECURITY/" "$SETTINGS_PY"
sed -i "/^# SECURITY WARNING: don't run with debug turned on in production!/ s/SECURITY/TODO: SECURITY/" "$SETTINGS_PY"
sed -i "/^ALLOWED_HOSTS = \[/i # TODO: Update ALLOWED_HOSTS for production!" "$SETTINGS_PY"
sed -i "/^ALLOWED_HOSTS = \[/s/\[\s*/[\n    'localhost', /" "$SETTINGS_PY"
sed -i "/^INSTALLED_APPS = \[/a \ \ \ \ 'corsheaders',\n \ \ \ 'rest_framework',\n \ \ \ 'api',\n \ \ \ 'backend'," "$SETTINGS_PY"
sed -i "/^MIDDLEWARE = \[/a \ \ \ \ 'corsheaders.middleware.CorsMiddleware'," "$SETTINGS_PY"
echo "
CORS_ALLOW_ALL_ORIGINS = True  # TODO: consider setting this to 'False' and specifying your frontend URL

# CORS_ALLOWED_ORIGINS = [
#     "http://localhost:3000",
# ]" >> "$SETTINGS_PY"
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo '
CORS_ALLOWS_CREDENTIALS = True

REST_FRAMEWORK = {
	"DEFAULT_AUTHENTICATION_CLASSES": (
       		"rest_framework_simplejwt.authentication.JWTAuthentication",
	),
	"DEFAULT_PERMISSION_CLASSES": [
		"rest_framework.permissions.IsAuthenticated",
	],
}

SIMPLE_JWT = {
	"ACCESS_TOKEN_LIFETIME": timedelta(minutes=30),
	"REFRESH_TOKEN_LIFETIME": timedelta(days=1),
}' >> "$SETTINGS_PY"
fi
if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]]; then
	echo '
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")' >> "$SETTINGS_PY"
fi

sudo npm install -g pnpm
echo -e "\e[33mScript recommendations: choose 'pnpm' for the package manager question and 'No' for the git repository question.\e[0m" 
pnpm dlx nuxi@latest init frontend
cd frontend/public && rm -rf robots.txt && touch robots.txt

echo '# robots.txt

User-agent: *
# Disallow: /example/

Allow: /

# Sitemap: https://example.com/sitemap.xml' >> robots.txt

cd .. && mkdir assets components layouts pages services && pnpm install -D @nuxtjs/tailwindcss && pnpm add -D prettier && touch constants.ts nuxt.d.ts components/AuthorizationWrapper.vue components/WaitLoadWrapper.vue pages/index.vue pages/not-found.vue services/api.ts services/auth.ts
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	pnpm install jwt-decode
	touch components/AuthorizationWrapper.vue pages/login.vue pages/logout.vue pages/register.vue pages/unauthorized.vue
fi
if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]] && [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	mkdir pages/new-password && mkdir pages/new-password/[uidb64] && touch pages/change-password.vue pages/new-password/[uidb64]/[token].vue
fi

echo 'export const ACCESS_TOKEN = "access";
export const REFRESH_TOKEN = "refresh";' >> constants.ts

sed -i "/devtools: { enabled: true }/a,\\
  telemetry: false,\\
  plugins: [],\\
  modules: [\"@nuxtjs/tailwindcss\"]," nuxt.config.ts

sed -i '/<NuxtRouteAnnouncer \/>/a\
    <NuxtPage />' app.vue

echo '<template>
  <div>
    <slot v-if="!loading" />
  </div>
</template>

<script setup lang="ts">
// Makes content wait for page load to render. Can be used to solve hydration mismatch errors.

const loading = ref(true);
const nuxtApp = useNuxtApp();
nuxtApp.hook("page:finish", () => {
  loading.value = false;
});
</script>' >> components/WaitLoadWrapper.vue

echo '<template>
  <WaitLoadWrapper></WaitLoadWrapper>
</template>' >> pages/index.vue

if [[ "$mail_answer" == "y" || "$mail_answer" == "Y" ]] && [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo '<template>
  <div>
    <h1>Change Password</h1>
    <form @submit.prevent="handleSubmit">
      <div>
        <label for="email">E-mail</label>
        <input type="email" id="email" v-model="email" required />
      </div>
      <button type="submit">Submit</button>
    </form>
    <div v-if="message">{{ message }}</div>
    <div v-if="error">{{ error }}</div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from "~/services/api";

const email = ref("");
const message = ref("");
const error = ref("");

const handleSubmit = async () => {
  message.value = "";
  error.value = "";

  try {
    const response = await apiFetch("/api/change-password/", {
      method: "POST",
      body: { email: email.value },
    });

    message.value =
      response.data.message || "Password reset link sent! Check your e-mail.";
  } catch (err) {
    if (err.response && err.response.data.message) {
      error.value = err.response.data.message;
    } else {
      error.value = "An error occurred. Please try again.";
    }
  }
};
</script>' >> pages/change-password.vue

echo '<template>
  <div>
    <h1>New Password</h1>
    <form @submit.prevent="handleSubmit">
      <div>
        <label for="new-password">New Password</label>
        <input
          type="password"
          id="new-password"
          v-model="newPassword"
          @input="handlePasswordChange"
          required
        />
      </div>
      <div>
        <label for="confirm-password">Confirm Password</label>
        <input
          type="password"
          id="confirm-password"
          v-model="confirmPassword"
          @input="handleConfirmPasswordChange"
          required
        />
      </div>
      <div v-if="passwordError">{{ passwordError }}</div>
      <button type="submit">Submit</button>
    </form>
    <div v-if="message">{{ message }}</div>
    <div v-if="error">{{ error }}</div>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from "~/services/api";

const route = useRoute();
const router = useRouter();

const uidb64 = route.params.uidb64 as string;
const token = route.params.token as string;

const newPassword = ref("");
const confirmPassword = ref("");
const message = ref("");
const error = ref("");
const passwordError = ref("");

const handlePasswordChange = () => {
  if (confirmPassword.value && newPassword.value !== confirmPassword.value) {
    passwordError.value = "Passwords do not match.";
  } else {
    passwordError.value = "";
  }
};

const handleConfirmPasswordChange = () => {
  if (newPassword.value && confirmPassword.value !== newPassword.value) {
    passwordError.value = "Passwords do not match.";
  } else {
    passwordError.value = "";
  }
};

const handleSubmit = async () => {
  message.value = "";
  error.value = "";

  if (newPassword.value !== confirmPassword.value) {
    error.value = "Passwords do not match.";
    return;
  }

  try {
    const response = await apiFetch(`/api/new-password/${uidb64}/${token}/`, {
      method: "POST",
      body: { new_password: newPassword.value },
    });

    message.value = "Password changed successfully! Redirecting...";
    setTimeout(() => {
      router.push("/login");
    });
  } catch (err) {
    if (err.response && err.response.data.message) {
      error.value = err.response.data.message;
    } else {
      error.value = "An error occurred. Please try again.";
    }
  }
};
</script>' >> pages/new-password/[uidb64]/[token].vue
fi

if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo '<template>
  <div>
    <h2>Login</h2>
    <form @submit.prevent="handleSubmit">
      <label for="username">E-mail:</label>
      <input id="username" v-model="username" type="text" required />

      <label for="password">Password:</label>
      <input id="password" v-model="password" type="password" required />

      <button type="submit" :disabled="loading">
        {{ loading ? "Logging in..." : "Login" }}
      </button>
    </form>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from "~/services/api";
import { ACCESS_TOKEN, REFRESH_TOKEN } from "~/constants";

const username = ref("");
const password = ref("");
const loading = ref(false);

const router = useRouter();

const handleSubmit = async () => {
  loading.value = true;

  try {
    const res = await apiFetch("/api/token/", {
      method: "POST",
      body: {
        username: username.value,
        password: password.value,
      },
    });

    localStorage.setItem(ACCESS_TOKEN, res.access);
    localStorage.setItem(REFRESH_TOKEN, res.refresh);
    router.push("/");
  } catch (error) {
    alert("Login failed: " + error);
  } finally {
    loading.value = false;
  }
};
</script>' >> pages/login.vue

echo '<template>
  <WaitLoadWrapper></WaitLoadWrapper>
</template>

<script setup lang="ts">
const router = useRouter();

onMounted(() => {
  localStorage.clear();
  router.push("/");
});
</script>' >> pages/logout.vue
fi

echo "<template>
  <div>
    <h1 class=\"text-2xl\">Page Not Found</h1>
    <p>The page you're looking for doesn't exist.</p>
  </div>
</template>" >> pages/not-found.vue

if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo '<template>
  <div>
    <h1>Register</h1>
    <form @submit.prevent="handleSubmit">
      <div>
        <label>First Name:</label>
        <input v-model="firstName" type="text" required />
      </div>
      <div>
        <label>Last Name:</label>
        <input v-model="lastName" type="text" required />
      </div>
      <div>
        <label>E-mail:</label>
        <input v-model="email" type="email" required />
      </div>
      <div>
        <label>Password:</label>
        <input
          type="password"
          v-model="password"
          @input="handlePasswordChange"
          required
        />
      </div>
      <div>
        <label>Confirm Password:</label>
        <input
          type="password"
          v-model="confirmPassword"
          @input="handleConfirmPasswordChange"
          required
        />
      </div>
      <p v-if="passwordError">{{ passwordError }}</p>
      <button type="submit" :disabled="loading">
        {{ loading ? "Registering..." : "Register" }}
      </button>
    </form>
  </div>
</template>

<script setup lang="ts">
import { apiFetch } from "../services/api";

const firstName = ref("");
const lastName = ref("");
const email = ref("");
const password = ref("");
const confirmPassword = ref("");
const passwordError = ref("");
const loading = ref(false);

const router = useRouter();

function handlePasswordChange(e: Event) {
  password.value = (e.target as HTMLInputElement).value;
  validatePasswordMatch();
}

function handleConfirmPasswordChange(e: Event) {
  confirmPassword.value = (e.target as HTMLInputElement).value;
  validatePasswordMatch();
}

function validatePasswordMatch() {
  passwordError.value =
    confirmPassword.value && password.value !== confirmPassword.value
      ? "Passwords do not match"
      : "";
}

async function handleSubmit() {
  if (passwordError.value) return;

  loading.value = true;

  try {
    await apiFetch("/api/user/register/", {
      method: "POST",
      body: {
        firstName: firstName.value,
        lastName: lastName.value,
        email: email.value,
        password: password.value,
      },
    });
    router.push("/login");
  } catch (error) {
    alert("Registration failed. Please try again.");
  } finally {
    loading.value = false;
  }
}
</script>' >> pages/register.vue

echo '<template>
  <div>
    <h1 class="text-2xl">Unauthorized</h1>
    <p>You do not have the required permissions to view this content.</p>
  </div>
</template>' >> pages/unauthorized.vue
fi

echo 'export function apiFetch(endpoint: string, options?: any) {
  return $fetch(endpoint, {
    baseURL: "http://localhost:8000",
    ...options,
  });
}' >> services/api.ts

if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	echo 'import { ref, onMounted } from "vue";
import { jwtDecode } from "jwt-decode";
import { useRouter } from "vue-router";
import { ACCESS_TOKEN, REFRESH_TOKEN } from "../constants";

interface DecodedToken {
  exp: number;
  roles: string[];
}

interface TokenResponse {
  access: string;
}

export function useAuth(requireAdmin: boolean = false) {
  const router = useRouter();
  const isAuthorized = ref<boolean | null>(null);
  const userRoles = ref<string[]>([]);

  const auth = async () => {
    const token = localStorage.getItem(ACCESS_TOKEN);
    if (!token) {
      isAuthorized.value = false;
      return;
    }

    const decoded: DecodedToken = jwtDecode(token);
    const tokenExpiration = decoded.exp;
    const now = Date.now() / 1000;

    if (tokenExpiration < now) {
      await refreshToken();
    } else {
      isAuthorized.value = true;
      userRoles.value = decoded.roles;
    }
  };

  const refreshToken = async () => {
    const refreshToken = localStorage.getItem(REFRESH_TOKEN);
    if (!refreshToken) {
      isAuthorized.value = false;
      return;
    }

    try {
      const res = await $fetch<TokenResponse>("/api/token/refresh/", {
        method: "POST",
        body: { refresh: refreshToken },
      });
      if (res && res.access) {
        localStorage.setItem(ACCESS_TOKEN, res.access);
        await auth();
      } else {
        isAuthorized.value = false;
      }
    } catch (error) {
      console.error("Error refreshing token:", error);
      isAuthorized.value = false;
    }
  };

  const isAdmin = () => userRoles.value.includes("Administrator");

  onMounted(async () => {
    await auth();
    if (isAuthorized.value === false) {
      router.push("/login");
    } else if (requireAdmin && !isAdmin()) {
      router.push("/unauthorized");
    }
  });

  return {
    isAuthorized,
    userRoles,
    isAdmin,
  };
}' >> services/auth.ts

echo '<template>
  <div>
    <template v-if="requireAdmin">
      <slot v-if="isAdmin()" />
      <div v-else-if="shouldRedirect">
        <router-link to="/login"></router-link>
      </div>
      <div v-else-if="showMessage">
        You do not have the required permissions to view this content.
      </div>
    </template>
    <template v-else>
      <slot v-if="isAuthorized" />
      <div v-else-if="shouldRedirect">
        <router-link to="/login"></router-link>
      </div>
      <div v-else-if="showMessage">
        You need to be logged in to view this content.
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
// If requireAdmin is set to true, the wrapped content will be exclusive to administrators. Otherwise, it will require just user-level authentication.
// If redirect is set to true, the user will be redirected to the login page.
// If message is set to true, a plaintext message will be rendered in place of the content. Otherwise, the content will just not be rendered.

import { useAuth } from "~/services/auth";

const props = defineProps<{
  requireAdmin?: boolean;
  shouldRedirect?: boolean;
  showMessage?: boolean;
}>();

const requireAdmin = computed(() => props.requireAdmin ?? false);
const shouldRedirect = computed(() => props.shouldRedirect ?? false);
const showMessage = computed(() => props.showMessage ?? false);

const { isAuthorized, isAdmin } = useAuth();
</script>' >> components/AuthorizationWrapper.vue
fi

cd .. && touch backend/.env frontend/.env

echo 'EMAIL_HOST_USER="example@example.com"
EMAIL_HOST_PASSWORD="#### #### #### ####"' >> backend/.env

./housekeep_project.sh

echo -e "\e[33mInitiating super user creation prompt. You can use this super user to log in to http://localhost:8000/admin/\e[0m" 
. $(pwd)/venv/bin/activate && python3 backend/manage.py createsuperuser
if [[ "$jwt_answer" == "y" || "$jwt_answer" == "Y" ]]; then
	python3 backend/manage.py create_groups
fi
deactivate

git init
echo -e "\e[33mScript notice: changing git branch name to 'main'.\e[0m" 
git branch -M main && git add . && git commit -m "setup commit"
if [ -n "$git_repo" ]; then
	git remote add origin $git_repo
	git push -u origin main
fi

./dev_project.sh
