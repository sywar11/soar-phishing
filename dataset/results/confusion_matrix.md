# Matrice de confusion du score

Jeu d'essai : 566 e-mails (200 phishing, 366 légitimes). Réputation en ligne : non. Passage par un signalement : oui.

## Seuil « suspect » (score ≥ 20) : envoi en validation

| | Prédit phishing | Prédit légitime |
|---|---|---|
| **Phishing réel** | VP = 133 | FN = 67 |
| **Légitime réel** | FP = 49 | VN = 317 |

Précision 0.731 · Rappel 0.665 · F1 0.696 · Exactitude 0.795 · Taux de faux positifs 0.134

## Seuil « malveillant » (score ≥ 70)

| | Prédit phishing | Prédit légitime |
|---|---|---|
| **Phishing réel** | VP = 5 | FN = 195 |
| **Légitime réel** | FP = 0 | VN = 366 |

Précision 1.0 · Rappel 0.025 · F1 0.049 · Exactitude 0.655 · Taux de faux positifs 0.0

## Balayage des seuils

| Seuil | VP | FN | FP | VN | Précision | Rappel | F1 |
|---|---|---|---|---|---|---|---|
| 10 | 151 | 49 | 165 | 201 | 0.478 | 0.755 | 0.585 |
| 20 | 133 | 67 | 49 | 317 | 0.731 | 0.665 | 0.696 |
| 30 | 92 | 108 | 26 | 340 | 0.78 | 0.46 | 0.579 |
| 40 | 59 | 141 | 14 | 352 | 0.808 | 0.295 | 0.432 |
| 50 | 25 | 175 | 11 | 355 | 0.694 | 0.125 | 0.212 |
| 60 | 15 | 185 | 1 | 365 | 0.938 | 0.075 | 0.139 |
| 70 | 5 | 195 | 0 | 366 | 1.0 | 0.025 | 0.049 |
| 80 | 2 | 198 | 0 | 366 | 1.0 | 0.01 | 0.02 |
| 90 | 1 | 199 | 0 | 366 | 1.0 | 0.005 | 0.01 |

## Erreurs au seuil principal

| Fichier | Famille | Vérité | Score | Règles |
|---|---|---|---|---|
| easy_ham_0005.eml | easy_ham | legit | 25 | reply_to_mismatch(+15);credential_request(+10) |
| easy_ham_0224.eml | easy_ham | legit | 25 | reply_to_mismatch(+15);credential_request(+10) |
| easy_ham_0243.eml | easy_ham | legit | 25 | reply_to_mismatch(+15);urgency(+10) |
| easy_ham_0293.eml | easy_ham | legit | 25 | reply_to_mismatch(+15);credential_request(+10) |
| hard_ham_0007.eml | hard_ham | legit | 50 | link_text_mismatch(+20);account_action(+20);url_credential_path(+10) |
| hard_ham_0014.eml | hard_ham | legit | 20 | link_text_mismatch(+20) |
| hard_ham_0016.eml | hard_ham | legit | 50 | link_text_mismatch(+20);account_action(+20);url_credential_path(+10) |
| hard_ham_0023.eml | hard_ham | legit | 25 | url_credential_path(+10);urgency(+10);html_form(+5) |
| hard_ham_0033.eml | hard_ham | legit | 20 | reply_to_mismatch(+15);html_form(+5) |
| hard_ham_0041.eml | hard_ham | legit | 35 | display_name_spoof(+20);url_credential_path(+10);html_form(+5) |
| hard_ham_0043.eml | hard_ham | legit | 35 | link_text_mismatch(+20);url_credential_path(+10);html_form(+5) |
| hard_ham_0055.eml | hard_ham | legit | 20 | link_text_mismatch(+20) |
| hard_ham_0060.eml | hard_ham | legit | 40 | url_lookalike(+30);url_credential_path(+10) |
| hard_ham_0061.eml | hard_ham | legit | 55 | url_lookalike(+30);url_credential_path(+10);credential_request(+10);html_form(+5) |
| hard_ham_0067.eml | hard_ham | legit | 30 | account_action(+20);credential_request(+10) |
| hard_ham_0077.eml | hard_ham | legit | 35 | display_name_spoof(+20);url_credential_path(+10);html_form(+5) |
| hard_ham_0084.eml | hard_ham | legit | 50 | link_text_mismatch(+20);account_action(+20);url_credential_path(+10) |
| hard_ham_0087.eml | hard_ham | legit | 35 | url_credential_path(+10);urgency(+10);credential_request(+10);html_form(+5) |
| hard_ham_0091.eml | hard_ham | legit | 20 | url_credential_path(+10);credential_request(+10) |
| hard_ham_0099.eml | hard_ham | legit | 55 | account_action(+20);url_credential_path(+10);urgency(+10);credential_request(+10);html_form(+5) |
| hard_ham_0119.eml | hard_ham | legit | 30 | account_action(+20);urgency(+10) |
| hard_ham_0138.eml | hard_ham | legit | 30 | reply_to_mismatch(+15);credential_request(+10);html_form(+5) |
| hard_ham_0144.eml | hard_ham | legit | 50 | link_text_mismatch(+20);account_action(+20);url_credential_path(+10) |
| hard_ham_0150.eml | hard_ham | legit | 20 | account_action(+20) |
| hard_ham_0160.eml | hard_ham | legit | 50 | link_text_mismatch(+20);account_action(+20);url_credential_path(+10) |
| hard_ham_0161.eml | hard_ham | legit | 40 | url_lookalike(+30);url_credential_path(+10) |
| hard_ham_0162.eml | hard_ham | legit | 20 | url_credential_path(+10);urgency(+10) |
| hard_ham_0178.eml | hard_ham | legit | 20 | urgency(+10);credential_request(+10) |
| hard_ham_0181.eml | hard_ham | legit | 40 | reply_to_mismatch(+15);url_shortener(+10);urgency(+10);html_form(+5) |
| hard_ham_0187.eml | hard_ham | legit | 25 | url_credential_path(+10);credential_request(+10);html_form(+5) |
| hard_ham_0193.eml | hard_ham | legit | 25 | url_credential_path(+10);credential_request(+10);html_form(+5) |
| hard_ham_0194.eml | hard_ham | legit | 50 | link_text_mismatch(+20);account_action(+20);url_credential_path(+10) |
| hard_ham_0198.eml | hard_ham | legit | 30 | account_action(+20);credential_request(+10) |
| hard_ham_0201.eml | hard_ham | legit | 35 | account_action(+20);url_credential_path(+10);html_form(+5) |
| hard_ham_0210.eml | hard_ham | legit | 35 | account_action(+20);url_credential_path(+10);html_form(+5) |
| hard_ham_0215.eml | hard_ham | legit | 50 | account_action(+20);external_claims_internal(+15);url_credential_path(+10);html_form(+5) |
| hard_ham_0218.eml | hard_ham | legit | 20 | account_action(+20) |
| hard_ham_0222.eml | hard_ham | legit | 25 | url_credential_path(+10);credential_request(+10);html_form(+5) |
| spam_0004.eml | spam | legit | 35 | reply_to_mismatch(+15);freemail_reply_to(+10);urgency(+10) |
| spam_0009.eml | spam | legit | 25 | payment_change(+15);urgency(+10) |
| spam_0017.eml | spam | legit | 55 | sender_lookalike(+30);reply_to_mismatch(+15);freemail_reply_to(+10) |
| spam_0025.eml | spam | legit | 25 | reply_to_mismatch(+15);urgency(+10) |
| spam_0055.eml | spam | legit | 25 | display_name_spoof(+20);html_form(+5) |
| spam_0067.eml | spam | legit | 25 | reply_to_mismatch(+15);url_ip(+10) |
| spam_0081.eml | spam | legit | 20 | account_action(+20) |
| spam_0102.eml | spam | legit | 30 | account_action(+20);urgency(+10) |
| spam_0120.eml | spam | legit | 65 | sender_lookalike(+30);account_action(+20);payment_change(+15) |
| spam_0138.eml | spam | legit | 20 | link_text_mismatch(+20) |
| spam_0186.eml | spam | legit | 25 | url_ip(+10);urgency(+10);html_form(+5) |
| nazario_2024_0007.eml | nazario_2024 | phishing | 15 | url_credential_path(+10);url_redirect_wrapper(+5) |
| nazario_2024_0014.eml | nazario_2024 | phishing | 10 | urgency(+10);auth_all_pass(+0) |
| nazario_2024_0019.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0021.eml | nazario_2024 | phishing | 18 | html_attachment(+10);spf_softfail(+8) |
| nazario_2024_0030.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0035.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0042.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0048.eml | nazario_2024 | phishing | 10 | urgency(+10) |
| nazario_2024_0061.eml | nazario_2024 | phishing | 10 | url_shortener(+10);auth_all_pass(+0) |
| nazario_2024_0065.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0073.eml | nazario_2024 | phishing | 15 | reply_to_mismatch(+15);url_shortener(+10);auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0088.eml | nazario_2024 | phishing | 5 | generic_greeting(+5);auth_all_pass(+0) |
| nazario_2024_0093.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0100.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0106.eml | nazario_2024 | phishing | 5 | url_suspicious_tld(+5);auth_all_pass(+0) |
| nazario_2024_0108.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0110.eml | nazario_2024 | phishing | 10 | credential_request(+10);auth_all_pass(+0) |
| nazario_2024_0112.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0122.eml | nazario_2024 | phishing | 15 | spf_fail(+15) |
| nazario_2024_0133.eml | nazario_2024 | phishing | 15 | reply_to_mismatch(+15);auth_all_pass(+0) |
| nazario_2024_0140.eml | nazario_2024 | phishing | 0 | credential_request(+10);auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0145.eml | nazario_2024 | phishing | 5 | url_redirect_wrapper(+5);auth_all_pass(+0) |
| nazario_2024_0150.eml | nazario_2024 | phishing | 5 | payment_change(+15);auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0166.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0168.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0169.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0171.eml | nazario_2024 | phishing | 5 | url_redirect_wrapper(+5);auth_all_pass(+0) |
| nazario_2024_0172.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0174.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0180.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0182.eml | nazario_2024 | phishing | 15 | reply_to_mismatch(+15);auth_all_pass(+0) |
| nazario_2024_0191.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0193.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0216.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0217.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0219.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0220.eml | nazario_2024 | phishing | 15 | spf_fail(+15) |
| nazario_2024_0227.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0237.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0255.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0258.eml | nazario_2024 | phishing | 15 | account_action(+20);url_redirect_wrapper(+5);auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0259.eml | nazario_2024 | phishing | 8 | spf_softfail(+8) |
| nazario_2024_0263.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0264.eml | nazario_2024 | phishing | 10 | credential_request(+10) |
| nazario_2024_0279.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0284.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0288.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0290.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0293.eml | nazario_2024 | phishing | 10 | html_attachment(+10) |
| nazario_2024_0294.eml | nazario_2024 | phishing | 15 | reply_to_mismatch(+15) |
| nazario_2024_0295.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0297.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0302.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0305.eml | nazario_2024 | phishing | 15 | reply_to_mismatch(+15);auth_all_pass(+0) |
| nazario_2024_0311.eml | nazario_2024 | phishing | 15 | external_claims_internal(+15);auth_all_pass(+0) |
| nazario_2024_0315.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0319.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0331.eml | nazario_2024 | phishing | 5 | url_redirect_wrapper(+5);auth_all_pass(+0) |
| nazario_2024_0332.eml | nazario_2024 | phishing | 15 | reply_to_mismatch(+15) |
| nazario_2024_0336.eml | nazario_2024 | phishing | 5 | generic_greeting(+5);auth_all_pass(+0) |
| nazario_2024_0342.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0);newsletter(-10) |
| nazario_2024_0372.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0379.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0384.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0386.eml | nazario_2024 | phishing | 0 | - |
| nazario_2024_0391.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0) |
| nazario_2024_0393.eml | nazario_2024 | phishing | 0 | auth_all_pass(+0);newsletter(-10) |
