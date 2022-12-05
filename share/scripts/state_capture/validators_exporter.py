from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options


def get_validators_count():
    try:
        chrome_options = Options()
        chrome_options.add_argument('--headless')
        chrome_options.add_argument('--no-sandbox')
        # chrome_options.add_argument('--disable-dev-shm-usage')

        driver = webdriver.Chrome(options=chrome_options)
        driver.get("https://solscan.io/validator")
        driver.implicitly_wait(15)
        elements = driver.find_element(By.XPATH,
                                       '//*[@id="root"]/section/main/div/div[2]/div/div[1]/div/div[1]/div[2]/span')
        elements.click()
        text = elements.text.replace(",", "")
        driver.close()
        return int(text)
    except:
        return 2105
