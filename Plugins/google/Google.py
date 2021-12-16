from random import random

from bs4 import BeautifulSoup
from requests import get

from config import UserHeader


def search(term, num_results=10, lang="en", proxy=None):
    usr_agent = {
        "User-Agent": random.choice(UserHeader.USER_Header)
}

    def fetch_results(search_term, number_results, language_code):
        escaped_search_term = search_term.replace(' ', '+')

        google_url = 'https://www.google.com/search?q={}&num={}&hl={}'.format(escaped_search_term, number_results+1, language_code)
        proxies = proxy
        print(proxies)
        response = get(google_url, headers=usr_agent, proxies=proxies)
        response.raise_for_status()
        return response.text

    def parse_results(raw_html):
        soup = BeautifulSoup(raw_html, 'html.parser')
        result_block = soup.find_all('div', attrs={'class': 'g'})
        for result in result_block:
            link = result.find('a', href=True)
            title = result.find('h3')
            if link and title:
                yield link['href']

    html = fetch_results(term, num_results, lang)
    return list(parse_results(html))


