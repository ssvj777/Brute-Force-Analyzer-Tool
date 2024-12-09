import tkinter as tk
from tkinter import font,filedialog, messagebox
import os
import winreg
import win32evtlog
import datetime
from datetime import datetime, timedelta
from prettytable import PrettyTable
import wx
import wx.adv



def open_application_module_1():
    server = "localhost"
    logtype = "Security"
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    def QueryEventLog(eventID, filename):
        logs = []
        if filename == "None":
            h = win32evtlog.OpenEventLog(server, logtype)
        else:
            h = win32evtlog.OpenBackupEventLog(server, filename)
        
        while True:
            events = win32evtlog.ReadEventLog(h, flags, 0)
            if events:
                for event in events:
                    if event.EventID & 0xFFFF == eventID: 
                        logs.append(event)
            else:
                break
        return logs


    def CountSuccessfulLogins(filename="None"):
        successful_logins = 0
        events = QueryEventLog(4624, filename)
        for event in events:
            successful_logins += 1
        return successful_logins

    def show_successful_logins(filename="None"):
        total_successful_logins = CountSuccessfulLogins(filename)
        
        login_table = PrettyTable()
        login_table.field_names = ["Total Successful Logins"]
        login_table.add_row([total_successful_logins])
        login_table_output = login_table.get_string()
        
        output_text.config(state=tk.NORMAL)
        output_text.delete("1.0", tk.END)
        insert_success_colored_text(login_table_output)
        output_text.config(state=tk.DISABLED)

        alert2 = run_analysis_alerts(filename)
        output_text.config(state=tk.NORMAL)
        insert_alert_colored_text(alert2)
        output_text.config(state=tk.DISABLED)

    def insert_success_colored_text(login_table_output):
        output_text.tag_configure("header", foreground="blue", font=("Helvetica", 12, "bold"))
        output_text.tag_configure("data", foreground="black")

        output_text.insert(tk.END, "\nTotal Successful Logins:\n", "header")
        output_text.insert(tk.END, login_table_output + "\n\n", "data")


    def DetectBruteForce(filename="None"):
        failures = {}
        events = QueryEventLog(4625, filename)
        for event in events:
            if int(event.StringInserts[10]) in [2, 8, 10]:
                account = event.StringInserts[1]
                timestamp = event.TimeGenerated.Format()
                if account in failures:
                    failures[account].append(timestamp)
                else:
                    failures[account] = [timestamp]
        return failures

    def show_failed_logins(filename="None"):
        failures = DetectBruteForce(filename)

        failures_table = PrettyTable()
        failures_table.field_names = ["Account", "Failed Login Count", "Timestamps"]
        for account, timestamps in failures.items():
            failures_table.add_row([account, len(timestamps), "\n".join(timestamps)])
        failures_table_output = failures_table.get_string()
        
        output_text.config(state=tk.NORMAL)
        output_text.delete("1.0", tk.END)
        insert_failed_colored_text(failures_table_output)
        output_text.config(state=tk.DISABLED)

        alert2 = run_analysis_alerts(filename)
        output_text.config(state=tk.NORMAL)
        insert_alert_colored_text(alert2)
        output_text.config(state=tk.DISABLED)

    def insert_failed_colored_text(failures_table_output):
        output_text.tag_configure("header", foreground="blue", font=("Helvetica", 12, "bold"))
        output_text.tag_configure("data", foreground="black")

        output_text.insert(tk.END, "\nFailed Login Attempts:\n", "header")
        output_text.insert(tk.END, failures_table_output + "\n\n", "data")


    def AlertOnContinuousFailures(failures, threshold=3):
        alerts = []
        for account, timestamps in failures.items():
            if len(timestamps) > threshold:
                consecutive_failures = 0
                for i in range(1, len(timestamps)):
                    time1 = datetime.strptime(timestamps[i-1], "%a %b %d %H:%M:%S %Y")
                    time2 = datetime.strptime(timestamps[i], "%a %b %d %H:%M:%S %Y")
                    if (time2 - time1).total_seconds() <= 60: 
                        consecutive_failures += 1
                        if consecutive_failures >= threshold:
                            alerts.append((account, timestamps[i-threshold:i+1]))
                            break
                    else:
                        consecutive_failures = 0
        return alerts

    def run_analysis_alert(filename="None"):
        failures = DetectBruteForce(filename)
        alerts = AlertOnContinuousFailures(failures)

        alerts_table = PrettyTable()
        alerts_table.field_names = ["Account", "Alert Timestamps"]
        if alerts:
            for account, timestamps in alerts:
                alerts_table.add_row([account, "\n".join(timestamps)])
            messagebox.showerror("Alert...", "Brute Force Event Detected !!!")
            alerts_output = alerts_table.get_string()
        else:
            alerts_output = "\nNo Brute Force Event Detected..."

        return alerts_output

    def run_analysis_alerts(filename="None"):
        failures = DetectBruteForce(filename)
        alert = AlertOnContinuousFailures(failures)

        alert_table = PrettyTable()
        alert_table.field_names = ["Account", "Alert Timestamps"]
        if alert:
            for account, timestamps in alert:
                alert_table.add_row([account, "\n".join(timestamps)])
            alert2 = alert_table.get_string()
        else:
            alert2 = "\nNo Brute Force Event Detected..."

        return alert2

    def insert_alert_colored_text(alerts_output):
        output_text.tag_configure("header", foreground="blue", font=("Bookman Old Style", 11, "bold"))
        output_text.tag_configure("data", foreground="black")
        output_text.tag_configure("alert", foreground="red")
        output_text.tag_configure("end", foreground="black", font=("Bookman Old Style", 11, "bold"))


        if "No Brute Force Event Detected..." in alerts_output:
            output_text.insert(tk.END, alerts_output, "end")
        else:
            output_text.insert(tk.END, "\nAlerts for Brute Force Event Detection !!!\n", "header")
            output_text.insert(tk.END, alerts_output, "alert")
            output_text.insert(tk.END, "\nConsider changing passwords and reviewing security settings...\n", "end")


    def open_file():
        filename = filedialog.askopenfilename(title="Select Event Log File", filetypes=[("Event Log Files", "*.evtx"), ("All Files", "*.*")])
        if filename:
            output_text.config(state=tk.NORMAL)
            output_text.delete("1.0", tk.END)
            output_text.config(state=tk.DISABLED)

            alerts_output = run_analysis_alert(filename)
            output_text.config(state=tk.NORMAL)
            insert_alert_colored_text(alerts_output)
            output_text.config(state=tk.DISABLED)

            frame.grid_rowconfigure(2, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_columnconfigure(1, weight=1)

            btn_success = tk.Button(frame, text="Show Successful Logins", command=lambda: show_successful_logins(filename))
            btn_success.grid(row=3, column=0, padx=5, pady=5)

            btn_failed = tk.Button(frame, text="Show Failed Logins", command=lambda: show_failed_logins(filename))
            btn_failed.grid(row=3, column=1, padx=5, pady=5)
        else:
            messagebox.showwarning("No file selected", "Please select a valid event log file.")


    def analyze_live_log():
        try:
            output_text.config(state=tk.NORMAL)
            output_text.delete("1.0", tk.END)
            
            alerts_output = run_analysis_alert()
            output_text.config(state=tk.NORMAL)
            insert_alert_colored_text(alerts_output)
            output_text.config(state=tk.DISABLED)

            frame.grid_rowconfigure(2, weight=1)
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_columnconfigure(1, weight=1)
            
            btn_success = tk.Button(frame, text="Show Successful Logins", command=lambda: show_successful_logins())
            btn_success.grid(row=3, column=0, padx=5, pady=5)

            btn_failed = tk.Button(frame, text="Show Failed Logins", command=lambda: show_failed_logins())
            btn_failed.grid(row=3, column=1, padx=5, pady=5)

        except Exception as e:
            messagebox.showerror("Error", str(e))


    root = tk.Tk()
    root.title("VJ's Brute Force Detector...")

    root.minsize(1000, 400)
    root.maxsize(1200, 800)

    frame = tk.Frame(root)
    frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=12)
    frame.pack_propagate(False)

    frame.grid_rowconfigure(1, weight=1)
    frame.grid_columnconfigure(0, weight=1)
    frame.grid_columnconfigure(1, weight=1)

    btn_open = tk.Button(frame, text="Analyze Event Logs File", command=open_file)
    btn_open.grid(row=0, column=0, padx=5, pady=5)

    btn_live = tk.Button(frame, text="Analyze Live Event Logs", command=analyze_live_log)
    btn_live.grid(row=0, column=1, padx=5, pady=5)

    output_text = tk.Text(frame, wrap=tk.WORD, width=100, height=30)
    output_text.grid(row=1, column=0, columnspan=2, pady=5, sticky='nsew')
    output_text.config(state=tk.DISABLED)

    root.mainloop()



def open_application_module_2():
    def get_installed_apps_on_date(selected_date):
        uninstall_keys = [
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
        ]

        apps_on_date = []
        for key in uninstall_keys:
            try:
                reg_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key)
                for i in range(0, winreg.QueryInfoKey(reg_key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(reg_key, i)
                        subkey = winreg.OpenKey(reg_key, subkey_name)
                        app_name = winreg.QueryValueEx(subkey, "DisplayName")[0]

                        try:
                            install_date_str = winreg.QueryValueEx(subkey, "InstallDate")[0]
                            if install_date_str:
                                install_date = datetime.strptime(install_date_str, "%Y%m%d").date()
                                if install_date == selected_date:
                                    apps_on_date.append(app_name)
                        except Exception as e:
                            continue
                    except Exception as e:
                        continue
            except Exception as e:
                continue
        return apps_on_date


    def get_uninstalled_apps_on_date(selected_date):
        event_log_type = "Setup"
        uninstalled_apps = []

        selected_date_start = datetime(selected_date.year, selected_date.month, selected_date.day)
        selected_date_end = selected_date_start + timedelta(days=1)

        try:
            event_log_handle = win32evtlog.OpenEventLog("localhost", event_log_type)
            event_read_flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

            events = True
            while events:
                events = win32evtlog.ReadEventLog(event_log_handle, event_read_flags, 0)
                for event in events:
                    if event.EventID == 1034:
                        try:
                            event_generated_time = datetime.strptime(event.TimeGenerated.Format(), "%a %b %d %H:%M:%S %Y")
                            if selected_date_start <= event_generated_time < selected_date_end:
                                app_name = event.StringInserts[0] if event.StringInserts else "Unknown Application"
                                uninstalled_apps.append(app_name)
                        except Exception:
                            continue

            win32evtlog.CloseEventLog(event_log_handle)
        except Exception:
            pass

        return uninstalled_apps
    
    def file_access_history(directory, selected_date):
        accessed_files = []
        selected_date = datetime.strptime(selected_date, '%Y-%m-%d').date()

        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    access_time = datetime.fromtimestamp(os.path.getatime(file_path)).date()
                    if access_time == selected_date:
                        accessed_files.append(file_path)
                except Exception as e:
                    continue
        return accessed_files



    class MainFrame(wx.Frame):
        def __init__(self, *args, **kw):
            super(MainFrame, self).__init__(*args, **kw)

            panel = wx.Panel(self)
            vbox = wx.BoxSizer(wx.VERTICAL)

            hbox_dir = wx.BoxSizer(wx.HORIZONTAL)
            self.dir_picker = wx.DirPickerCtrl(panel, message="Select a Folder")
            hbox_dir.Add(wx.StaticText(panel, label="Select a Folder or Directory:"), flag=wx.RIGHT, border=8)
            hbox_dir.Add(self.dir_picker, proportion=1)
            vbox.Add(hbox_dir, flag=wx.EXPAND | wx.ALL, border=10)

            hbox_date = wx.BoxSizer(wx.HORIZONTAL)
            self.date_picker = wx.adv.DatePickerCtrl(panel, style=wx.adv.DP_DROPDOWN)
            hbox_date.Add(wx.StaticText(panel, label="Select Date:"), flag=wx.RIGHT, border=8)
            hbox_date.Add(self.date_picker, proportion=1)
            vbox.Add(hbox_date, flag=wx.EXPAND | wx.ALL, border=10)

            search_btn = wx.Button(panel, label="Analyze Files and Applications History")
            vbox.Add(search_btn, flag=wx.ALIGN_CENTER | wx.ALL, border=10)
            search_btn.Bind(wx.EVT_BUTTON, self.find_files_and_apps)

            self.result_label = wx.TextCtrl(panel, style=wx.TE_MULTILINE | wx.TE_READONLY | wx.TE_RICH2, size=(400, 300))
            vbox.Add(self.result_label, proportion=1, flag=wx.EXPAND | wx.ALL, border=10)

            panel.SetSizer(vbox)
            self.SetSize((500, 600))

        def insert_colored_text(self, header, data, header_style, data_style, none_style, none_message):
            """Inserts colored and styled text into the wx.TextCtrl"""
            self.result_label.SetDefaultStyle(header_style)
            self.result_label.AppendText(header)

            if data:
                self.result_label.SetDefaultStyle(data_style)
                self.result_label.AppendText(data + "\n\n")
            else:
                self.result_label.SetDefaultStyle(none_style)
                self.result_label.AppendText(none_message + "\n\n")

        def find_files_and_apps(self, event):
            directory = self.dir_picker.GetPath()
            selected_date = self.date_picker.GetValue().FormatISODate()

            if not selected_date:
                wx.MessageBox("Please select a date.", "Input Error", wx.ICON_WARNING)
                return

            self.result_label.Clear()

            header_style = wx.TextAttr(wx.Colour(0, 0, 255), font=wx.Font(12, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD, faceName="Bookman Old Style"))
            data_style = wx.TextAttr(wx.Colour(255, 0, 0), font=wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL, faceName="Bookman Old Style"))
            none_style = wx.TextAttr(wx.Colour(0, 0, 0), font=wx.Font(11, wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_BOLD, faceName="Bookman Old Style"))

            if directory:
                files = file_access_history(directory, selected_date)
                if files:
                    self.insert_colored_text(f"Files accessed on {selected_date}:\n", "\n".join(files), header_style, data_style, none_style, none_message="")
                else:
                    self.insert_colored_text(f"Files accessed on {selected_date}:\n", None, header_style, data_style, none_style, none_message=f"No files accessed on {selected_date}.")

            apps_installed = get_installed_apps_on_date(datetime.strptime(selected_date, '%Y-%m-%d').date())

            if apps_installed:
                self.insert_colored_text(f"Applications installed on {selected_date}:\n", "\n".join(apps_installed), header_style, data_style, none_style, none_message="")
            else:
                self.insert_colored_text(f"Applications installed on {selected_date}:\n", None, header_style, data_style, none_style, none_message=f"No applications installed on {selected_date}.")

            apps_uninstalled = get_uninstalled_apps_on_date(datetime.strptime(selected_date, '%Y-%m-%d').date())

            if apps_uninstalled:
                self.insert_colored_text(f"Applications uninstalled on {selected_date}:\n", "\n".join(apps_uninstalled), header_style, data_style, none_style, none_message="")
            else:
                self.insert_colored_text(f"Applications uninstalled on {selected_date}:\n", None, header_style, data_style, none_style, none_message=f"No applications uninstalled on {selected_date}.")


    if __name__ == "__main__":
        app = wx.App(False)
        frame = MainFrame(None, title="VJ's Files & Applications History Analyzer...")
        frame.Show()
        app.MainLoop()



root = tk.Tk()
frame = tk.Frame(root)
frame.pack()

root.title("VJ's Brute Force Analyzer Tool")
root.geometry("750x700")

main_frame = tk.Frame(root)
main_frame.pack(fill=tk.BOTH, expand=True)

left_frame = tk.Frame(main_frame, width=250, bg="#D3D3D3")
left_frame.pack(side=tk.LEFT, fill=tk.Y)
left_frame.pack_propagate(False)

right_frame = tk.Frame(main_frame)
right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

label = tk.Label(left_frame, text="Select an Analyzer to Run:", font=("Helvetica", 15, "bold"))
label.pack(pady=10)

output_text = tk.Text(right_frame, wrap=tk.WORD, width=60, height=30, state=tk.DISABLED)
output_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

btn_font = font.Font(family="Bookman Old Style", size=10, weight="bold")
btn_app1 = tk.Button(left_frame, text="Brute Force Event Analyzer", command=open_application_module_1, width=28, height=2, font=btn_font)
btn_app1.pack(pady=10)

btn_app2 = tk.Button(left_frame, text="Files & App's History Analyzer", command=open_application_module_2, width=28, height=2, font=btn_font)
btn_app2.pack(pady=10)

root.mainloop()