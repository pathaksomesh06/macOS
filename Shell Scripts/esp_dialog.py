# Copyright (c) 2024 [Somesh Pathak]. All rights reserved.
# This script automates Ubuntu installation and Intune enrollment to provide a seamless enterprise device setup experience.
# Disclaimer: This script is provided "as-is" without any warranties of any kind, either express or implied.


# esp_dialog.py
import gi
gi.require_version('Gtk', '3.0')
from gi.repository import Gtk, GLib, Gdk, Pango
import json
import os
import time
import threading

class ESPDialog(Gtk.Window):
   def __init__(self):
       Gtk.Window.__init__(self, title="Device Setup")
       self.set_default_size(600, 400)
       self.set_position(Gtk.WindowPosition.CENTER)
       
       # Apply CSS styling
       css_provider = Gtk.CssProvider()
       css = b"""
           .header-text { 
               font-size: 18px; 
               font-weight: bold; 
               margin-bottom: 10px;
           }
           .status-text { 
               font-size: 14px; 
               color: #666666;
           }
           .progress-bar { 
               min-height: 8px;
           }
           .step-done { 
               color: #2eb82e;
               font-weight: bold;
           }
           .step-current { 
               color: #0066cc;
               font-weight: bold;
           }
           .step-pending { 
               color: #666666;
           }
           .step-icon {
               font-family: "Font Awesome 5 Free";
               font-size: 16px;
               margin-right: 10px;
           }
       """
       css_provider.load_from_data(css)
       Gtk.StyleContext.add_provider_for_screen(
           Gdk.Screen.get_default(),
           css_provider,
           Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
       )

       # Main container
       self.box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
       self.box.set_margin_top(20)
       self.box.set_margin_bottom(20)
       self.box.set_margin_start(20)
       self.box.set_margin_end(20)
       self.add(self.box)

       # Header
       header_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=5)
       header_box.set_margin_bottom(20)
       
       header_label = Gtk.Label(label="Setting up your device")
       header_label.get_style_context().add_class("header-text")
       
       subheader_label = Gtk.Label(
           label="This process will install and configure required components.\nPlease don't turn off your device during setup."
       )
       subheader_label.get_style_context().add_class("status-text")
       
       header_box.pack_start(header_label, True, True, 0)
       header_box.pack_start(subheader_label, True, True, 0)
       
       self.box.pack_start(header_box, False, False, 0)

       # Steps container
       self.steps_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
       self.box.pack_start(self.steps_box, True, True, 0)

       # Progress bar
       self.progress_bar = Gtk.ProgressBar()
       self.progress_bar.get_style_context().add_class("progress-bar")
       self.progress_bar.set_margin_top(20)
       self.progress_bar.set_margin_bottom(10)
       self.box.pack_start(self.progress_bar, False, False, 0)

       # Status text
       self.status_label = Gtk.Label()
       self.status_label.get_style_context().add_class("status-text")
       self.box.pack_start(self.status_label, False, False, 0)

       # Initialize steps with icons
       self.steps = [
           ("🔍", "Checking system requirements"),
           ("📦", "Installing required packages"),
           ("🔄", "Setting up Microsoft repository"),
           ("💻", "Installing Intune Company Portal"),
           ("🛡️", "Installing Microsoft Defender"),
           ("⚙️", "Configuring security settings"),
           ("✓", "Verifying installation")
       ]
       self.step_labels = []
       self.current_step = 0

       for icon, step_text in self.steps:
           step_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
           
           # Icon
           icon_label = Gtk.Label()
           icon_label.set_markup(f"<span size='larger'>{icon}</span>")
           step_box.pack_start(icon_label, False, False, 0)
           
           # Step label
           label = Gtk.Label(label=step_text)
           label.set_halign(Gtk.Align.START)
           label.get_style_context().add_class("step-pending")
           step_box.pack_start(label, True, True, 0)
           
           self.steps_box.pack_start(step_box, False, False, 0)
           self.step_labels.append((label, icon_label))

       # Status file monitoring
       self.status_file = "/var/tmp/esp-setup/esp-progress"
       self.monitor_thread = threading.Thread(target=self.monitor_status, daemon=True)
       self.monitor_thread.start()

   def update_progress(self, progress, message=None):
       def update():
           self.progress_bar.set_fraction(progress / 100)
           if message:
               self.status_label.set_text(message)
           
           # Update step styling
           current_step = int((progress * len(self.steps)) / 100)
           for i, (label, icon) in enumerate(self.step_labels):
               if i < current_step:
                   label.get_style_context().remove_class("step-pending")
                   label.get_style_context().remove_class("step-current")
                   label.get_style_context().add_class("step-done")
               elif i == current_step:
                   label.get_style_context().remove_class("step-pending")
                   label.get_style_context().remove_class("step-done")
                   label.get_style_context().add_class("step-current")
               else:
                   label.get_style_context().remove_class("step-done")
                   label.get_style_context().remove_class("step-current")
                   label.get_style_context().add_class("step-pending")
           
           return False
       
       GLib.idle_add(update)

   def monitor_status(self):
       while True:
           try:
               if os.path.exists(self.status_file):
                   with open(self.status_file, 'r') as f:
                       try:
                           data = json.load(f)
                           self.update_progress(
                               data.get('progress', 0),
                               data.get('message', '')
                           )
                           
                           if data.get('complete', False):
                               GLib.idle_add(self.on_completion)
                               break
                       except json.JSONDecodeError:
                           # Handle simple progress file
                           progress = float(f.read().strip())
                           self.update_progress(progress)
               time.sleep(0.5)
           except Exception as e:
               print(f"Error monitoring status: {e}")
               time.sleep(1)

   def on_completion(self):
       dialog = Gtk.MessageDialog(
           transient_for=self,
           modal=True,
           message_type=Gtk.MessageType.INFO,
           buttons=Gtk.ButtonsType.OK,
           text="Device Setup Complete"
       )
       dialog.format_secondary_text(
           "Your device has been successfully configured and is ready to use."
       )
       dialog.run()
       dialog.destroy()
       self.close()
       return False

def show_esp_dialog():
   win = ESPDialog()
   win.connect("destroy", Gtk.main_quit)
   win.show_all()
   Gtk.main()

if __name__ == "__main__":
   show_esp_dialog()