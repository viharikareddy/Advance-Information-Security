import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import sys
from tkinter import *
from PIL import ImageTk, Image
import threading

main_windowScreen = Tk()

main_windowScreen.geometry("900x500")
main_windowScreen.title("Detect XSS vulnerability")


Label(main_windowScreen, text= "Detect XSS vulnerable Website", fg='red',font=("Times New Roman",35)).place(x=30,y=80,relwidth=1)

#this takes image to add it on title page.
img = ImageTk.Image.open(r"D:\Downloads\xss.jpeg")
imag = img.resize((500,200), Image.ANTIALIAS)
cover_image= ImageTk.PhotoImage(imag)
imglabel = Label(main_windowScreen, image = cover_image).place(x=230,y=150)

#this function is responsible for generating UI pop up
def on_click():


    other_window = Toplevel(main_windowScreen)
    other_window.geometry("900x500")
    other_window.title("Detect XSS vulnerability")
    Label(other_window, text= "Enter URL below", fg='red',font=("Times New Roman",35)).place(x=30,y=80,relwidth=1)

    url2=StringVar()
    url1 = Entry(other_window, width = 50, borderwidth = 5,textvariable=url2).place(x=320,y=150)

    def on_click1():
        output = Toplevel(other_window)
        output.geometry("900x500")
        output.title("Detect XSS vulnerability")
        out = Toplevel(other_window)
        out.geometry("900x500")
        out.title("Detect XSS vulnerability")

        #requests module is used to send requests to paarticular url and then html content is parsed.
        #below function fetches form details (params) from web pages.
        def extract_forms(url):

            b_s_ = bs(requests.get(url).content, "html.parser")
            return b_s_.find_all("form")

        #once it fetches html content from above function below function is responsible for getting attributes like action type, method like post or get..etc. returns them as soup objects (data_to_dictionary).
        def get_form_data(form):

            data = {}

            f_attr_get_actn = form.attrs.get("action")
            action = f_attr_get_actn.lower()


            f_attr_get_m =form.attrs.get("method", "get")
            method = f_attr_get_m.lower()


            inpts = get_input_data(form)
    
            data_to_dictionary(action, data, inpts, method)
            return data

        def data_to_dictionary(action, data, inputs, method):
            data["action"] = action
            data["method"] = method
            data["inputs"] = inputs

    #below function creates list called all_inputs and then once it finds input type as text and name it returns results to all_inputs.
        def get_input_data(form):
            all_inpts = []
            for tag_inpts in form.find_all("input"):
                inpt = tag_inpts.attrs.get("type", "text")
                inpt_name_ = tag_inpts.attrs.get("name")
                all_inpts.append({"type": inpt, "name": inpt_name_})
            return all_inpts
        
    #below is function to submit form

        def form_submit(form_data, url, value):

            dest_url = urljoin(url, form_data["action"])

            data = replace_values(form_data, value)

            return form_method(data, form_data, dest_url)

        def replace_values(form_data, value):
            inpts = form_data["inputs"]
            data = {}
            for inpt in inpts:

                if inpt["type"] == "search" or inpt["type"] == "text" or inpt["type"] == "email" or inpt["type"] == "url":
                    inpt["value"] = value
                inpt_name_ = inpt.get("name")
                inpt_val = inpt.get("value")

                if inpt_name_ and inpt_val:

                    data[inpt_name_] = inpt_val
            return data

        def form_method(data, form_data, target_url):
            if form_data["method"] == "post":
                return requests.post(target_url, data=data)
            else:
                return requests.get(target_url, params=data)

        # this function checks no_of_forms on the target website for example like detected 1 form on target website to test for xss.
        def xss_scanner(url):

            no_of_forms = extract_forms(url)
            print(f"[+] Detected {len(no_of_forms)} form(s) on URL: {url}.")
            with open('payloads.txt', 'r') as f:
                js_script = [line.strip() for line in f]
            #js_script = "<Script>alert(document.domain)</scripT> "

            is_vulnerable = False
            Label(output, text= "Website is Safe",
                          fg='green',
                          font=("Times New Roman",35)).place(x=30,y=80,relwidth=1)


            return detect_vuln(no_of_forms, is_vulnerable, js_script, url)

        #this function triggers get_all_forms() and then if js_script gets reflected in response forms then it classifies it as malicious site other wise as safe website.
        def detect_vuln(forms_, xss_vulnerable, js_script, url_):
            for form in forms_:
                form_data = get_form_data(form)
                for i in js_script:
                    content = form_submit(form_data, url_, i).content.decode()
                    if i in content:
                        xss_vulnerable = True
                        print(f"[+] XSS Detected on {url_}")
                        print(f"[+] Form data:")
                        print(form_data)
                        print("Is XSS Vulnerable: ")
                        Label(output, text= "!!!!!!!!!!!!Dangerous Website!!!!!!!!!!!!!",
                              fg='red',
                              font=("Times New Roman",35)).place(x=30,y=80,relwidth=1)


            return xss_vulnerable


        if __name__ == "__main__":
            url=url2.get()
        #url_ = input("Enter the website URl to detect vulnerability: ");
            print(xss_scanner(url))
        other_window.mainloop()

    button = Button(other_window, text="Search",font=("Times New Roman",18,'bold'),  command=on_click1).place(x=420,y=185,width=120,height=30)


# https://xss-game.appspot.com/level1/frame
button = Button(main_windowScreen, text="Start",font=("Times New Roman",18,'bold'),  command=threading.Thread(target=on_click).start).place(x=430,y=370,width=120,height=30)

main_windowScreen.mainloop()
