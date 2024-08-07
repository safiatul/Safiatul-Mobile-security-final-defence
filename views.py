from django.shortcuts import render,redirect
from django.urls import reverse
from django.views.generic.base import TemplateView
from django.contrib.auth.models import User, auth
from django.contrib.auth import logout as auth_logout
from django.contrib import messages
import os
import requests
from django.contrib.auth import login
# Create your views here.
from django.shortcuts import render, redirect
from django.views.generic import TemplateView
from .models import MalwareDetection
from django.core.files.storage import FileSystemStorage
import clamd
from .models import MalwareDetection  # Assuming you have defined MalwareDetection model
from django.conf import settings
class Index(TemplateView):
    template_name = "detector/index.html"
    def get_context_data(self, **kwargs):
        context= super().get_context_data(**kwargs)
        context['items'] = MalwareDetection.objects.all()
        return context

    def post(self, request, *args, **kwargs):
        uploaded_file = request.FILES['file']
        fs = FileSystemStorage()
        file_path = fs.save(uploaded_file.name, uploaded_file)
        file_location = fs.path(file_path)
        user= None
        if request.user:
            user=request.user
        api_key = settings.VIRUSTOTAL_API_KEY
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        files = {'file': (uploaded_file.name, open(file_location, 'rb'))}
        params = {'apikey': api_key}
        alert="success"
        try:
            response = requests.post(url, files=files, params=params)
            if response.status_code == 200:
                scan_id = response.json().get('scan_id')
                message = f"File uploaded successfully. Scan ID: {scan_id}"
                
                # Check the scan results
                report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
                report_params = {'apikey': api_key, 'resource': scan_id}
                report_response = requests.get(report_url, params=report_params)

                if report_response.status_code == 200:
                    report = report_response.json()
                    positives = report.get('positives', 0)
                    if positives > 0:
                        for antivirus, scan in report.get('scans', {}).items():
                            if scan.get('detected'):
                                malware_name = scan.get('result')
                                if request.user:
                                    MalwareDetection.objects.create(file_name=uploaded_file.name, malware_name=malware_name,user=user)
                                else:
                                    MalwareDetection.objects.create(file_name=uploaded_file.name, malware_name=malware_name)
                                message = f"Malware detected: {malware_name}"
                                alert="danger"
                                break
                    else:
                        message = "The file is clean."
                else:
                    message = "Error retrieving scan report."
                    alert="danger"
            else:
                message = "Error uploading file to VirusTotal."
                alert="danger"
        except Exception as e:
            message = f"Error scanning file: {str(e)}"
            alert="danger"

        context = {
            'message': message,
            'alert': alert

        }
        return render(request, self.template_name, context)

class Dashboard(TemplateView):
    template_name = "detector/dashboard.html"
    def get_context_data(self, **kwargs):
        context= super().get_context_data(**kwargs)
        context['items'] = MalwareDetection.objects.filter(user=self.request.user)
        return context
    def post(self, request, *args, **kwargs):
        uploaded_file = request.FILES['file']
        fs = FileSystemStorage()
        file_path = fs.save(uploaded_file.name, uploaded_file)
        file_location = fs.path(file_path)
        user= None
        if request.user:
            user=request.user
        api_key = settings.VIRUSTOTAL_API_KEY
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        files = {'file': (uploaded_file.name, open(file_location, 'rb'))}
        params = {'apikey': api_key}
        alert="success"
        try:
            response = requests.post(url, files=files, params=params)
            if response.status_code == 200:
                scan_id = response.json().get('scan_id')
                message = f"File uploaded successfully. Scan ID: {scan_id}"
                
                # Check the scan results
                report_url = 'https://www.virustotal.com/vtapi/v2/file/report'
                report_params = {'apikey': api_key, 'resource': scan_id}
                report_response = requests.get(report_url, params=report_params)

                if report_response.status_code == 200:
                    report = report_response.json()
                    positives = report.get('positives', 0)
                    if positives > 0:
                        for antivirus, scan in report.get('scans', {}).items():
                            if scan.get('detected'):
                                malware_name = scan.get('result')
                                MalwareDetection.objects.create(file_name=uploaded_file.name, malware_name=malware_name,user=user)
                                message = f"Malware detected: {malware_name}"
                                alert="danger"
                                break
                    else:
                        message = "The file is clean."
                else:
                    message = "Error retrieving scan report."
                    alert="danger"
            else:
                message = "Error uploading file to VirusTotal."
                alert="danger"
        except Exception as e:
            message = f"Error scanning file: {str(e)}"
            alert="danger"

        context = {
            'message': message,
            'alert': alert

        }
        return render(request, self.template_name, context)
class Login(TemplateView):
    template_name = "detector/pages-login.html"
    
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')
        return render(request, self.template_name)
    
    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')
        
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = auth.authenticate(username=username, password=password)
        
        if user is not None:
            auth.login(request, user)
            return redirect('dashboard')
        else:
            return render(request, self.template_name, {'error': 'Invalid username or password'})
class Signup(TemplateView):
    template_name = "detector/pages-signup.html"
    
    def get(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')
        return render(request, self.template_name)
    
    def post(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect('dashboard')
        
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')

        if password != password2:
            return render(request, self.template_name, {'error': 'Passwords do not match'})

        if User.objects.filter(username=username).exists():
            return render(request, self.template_name, {'error': 'Username already exists'})

        if User.objects.filter(email=email).exists():
            return render(request, self.template_name, {'error': 'Email already exists'})

        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()
        login(request, user)
        return redirect('dashboard')
    

#logout
from django.contrib.auth import logout as auth_logout

def logout(request):
    auth_logout(request)
    return redirect(reverse('index'))  

