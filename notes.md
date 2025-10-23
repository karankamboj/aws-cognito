kkamboj@OEC1092 Auth % curl -X POST "http://localhost:8000/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "TempPassword123!",
    "first_name": "Test",
    "last_name": "User"
  }'

{"message":"User registered successfully","user_sub":"54682448-e011-70a2-d494-6a2836152b30","confirmation_required":true}%   

kkamboj@OEC1092 Auth % 

{"detail":"User account not confirmed. Please check your email for confirmation instructions."}%                                                                                     
kkamboj@OEC1092 Auth % curl -X POST "http://localhost:8000/login" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "karankamboj928",
    "password": "Karanshan@28"
  }'
{"access_token":"eyJraWQiOiJkZXpOaUlPVUJ1UUpXOFNjMTdxXC9OQlRNMGtFMktIVUpoZjhKWlk3VHdsWT0iLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiI2NDg4NTQ0OC00MGExLTcwNjAtZTg5My0zODhkYmMyMzI4ODkiLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0xLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMV95ODJQejVzYVYiLCJjbGllbnRfaWQiOiIzYXIzMXE3bXJqcGg0aWg0bWdidWV1dGpyNSIsIm9yaWdpbl9qdGkiOiJmOWE0OWQ5ZC1kYmNhLTRmMGQtOGMyNy03M2VjNGQ5ODQwNGIiLCJldmVudF9pZCI6IjA3MmZiNWFkLTAxZDUtNGEyNy05YzY2LTJlYzFjOTIwYmZjZiIsInRva2VuX3VzZSI6ImFjY2VzcyIsInNjb3BlIjoiYXdzLmNvZ25pdG8uc2lnbmluLnVzZXIuYWRtaW4iLCJhdXRoX3RpbWUiOjE3NTk2NDQ3NDEsImV4cCI6MTc1OTY0ODM0MSwiaWF0IjoxNzU5NjQ0NzQxLCJqdGkiOiJiMjg1NDM0OS01OTRkLTRmMDItODdiYS0xZjk5OGQzNTQzOGIiLCJ1c2VybmFtZSI6ImthcmFua2FtYm9qOTI4In0.NYp1h5l1sdoOqTfeyzBR1Dst1igikTozB4qqtc-enWJlOHsCOiC_ovDnT2VZlhEkC_sacJNZIINI8wHCWlYfYwWrfVTgjxezpx_eoAGB8gzFVZRpMkHCE3h6Z-Bo6Bhuk6EMcsNRL0JxsNFfzb54_tXSjykkrFlKP5dGtN3uJDUTCgSb98hjD2UhcuqAza19-X48r7qmaQ2gfZxDT03R0CL7tQFhU8eotl1Ir299Jw7j_pQV2sZ7tHeLywjvOMe07nFPDfADRnhReJ_JgcT_UztsfpQZzAlDXaJRqFiJdxmSINfgSUPnkZp6yGcKnMnnYci4bdCdelonTN2iQ06ODQ","id_token":"eyJraWQiOiI0OWF3YW9rUU51U2NOZlRXNDgrdmZnMGl2NTVIaCtRT2NvOVhUSk9EOEtVPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI2NDg4NTQ0OC00MGExLTcwNjAtZTg5My0zODhkYmMyMzI4ODkiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tXC91cy1lYXN0LTFfeTgyUHo1c2FWIiwiY29nbml0bzp1c2VybmFtZSI6ImthcmFua2FtYm9qOTI4Iiwib3JpZ2luX2p0aSI6ImY5YTQ5ZDlkLWRiY2EtNGYwZC04YzI3LTczZWM0ZDk4NDA0YiIsImF1ZCI6IjNhcjMxcTdtcmpwaDRpaDRtZ2J1ZXV0anI1IiwiZXZlbnRfaWQiOiIwNzJmYjVhZC0wMWQ1LTRhMjctOWM2Ni0yZWMxYzkyMGJmY2YiLCJ0b2tlbl91c2UiOiJpZCIsImF1dGhfdGltZSI6MTc1OTY0NDc0MSwiZXhwIjoxNzU5NjQ4MzQxLCJpYXQiOjE3NTk2NDQ3NDEsImp0aSI6ImZmYmE0MGE4LTg3MWYtNDJmNC1iZDk3LWU0MThhNzhmZGY0ZiIsImVtYWlsIjoia2FyYW5rYW1ib2o5MjhAZ21haWwuY29tIn0.k8d87JM-bM3_UpZrHTS7l8CjRHDtv5uS_QocYE2HMIPuofnAlCe_JAzXfUAHlQBa9h0Mj7WXPeNeWlUPt7QzzwMlyRjSxKHWaDP0HV9I-CaqmVpFh4Kd2XJd-GpmbvgcoR2R8IMVX0-CaINjViGqEd2XgGvYP1GlpKqJx85MuYCFM83E6N_a4HVeoPhGmNyo9NuEnYxslv5RTvHi2v2TUBYhtFlF2OmW8Ko6oS35VENShggveI1y3_aZCursm5nJA0xnkqQA_kBsdWIvx1MHqH8A7b_H7pQTefuDb65XUx60sQYArJBm33akuRTJ3oEXH69M8xRjco3RmIVNNMOlFA","refresh_token":"eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAifQ.Zvtr4h6duwcZS3K37ohfNyytCUmJYLBU8d13Vmj2qR_VM6nvXi6LiDeh5T_fnv8ivXHk4SFl-G_3H7UNUypxEtg2Q4s80EqMuifnT0bTs07x51Unh-MLz__gXBiNTdRWtMUcsgva7-U31bMhnirVDavBC7E1FW6gaqv_XmbFi2O18hfcpV_gryqlhpokILoO4HO2ZrT3nAaJTudF3MzAmX8xYao3NpcX9qgFBk_Xa7FRyZaTZjBF4Pdub1rFOBssfCc5v9ZV0b3bseR3sWOqX96jQfREZZe2vPUVHD-Z25_fk_cg6r32LOZxpSXbd54Fvbi_6jMkT_g3pdJxNjFBpw.MwtwgDiqgY-vXTPn.DMXGmIx9Rw0YpqvpLM3OgS-lro0oNMq8qe0XiTfewWyErXPsGcTwTf0_He7_7VJ_7MluVB7ldfL9tc2OMFC6vp9hruqPWr9h_7YpOIxc4G1c7nXzq4OMnUwZUenYfoStVPz_cjrlx1Bq0-rvEOqcRdWif7naKeCwGmFJN92me4DAXHakwII-IncW3eiL47GSVCWaEZbmMXV4nObCprUmi5ahJ4JgnxKBnWYN6GQHPBsIIpnvK1N3yU9kH3J2a8pjThItCZ8_9J5O5qC1jUmwJWx6Z2B8aR9lWHA5dpkVcrqRpwN1u-AzdyfzZsiGDHAG4cSw8ul8QD6R37uPjEKuBrJuJvM8OgTw8p4R-UWc9uB-JrUT_6KoAYVy-d7M6bkbhzWqIMvbtlhxTjUSo-QcBJVAN9JUEeaV14sEN3bDSYalRgvxx0RLjXJ0Si5r17ZBCiDDNFI6gyxw8X2tVk9QvJBrbwcRRbRaVl_vuckJTgqLDiP1aYkmodDrl9HmsH4pIccplbaI9ZhNaNNNG7ScFYTgYpWp9lbzsBc1_oP5E4dNJNQKdoqvnw0nNHsfIeuLdReKpJocNH0JiuWDTW_dqUb6d1g6oL8o1qIxLD6lvrYAyRbKi1SbZJGOcYRvPQPG1E-dL5mVCE-vKkvc0ox39SABDTI50UZt3Gl70ShAMkbRsX9JGCx-F4_ORH0U--F2t2L6GpCvgY8hlo9GWelrvTcZ03Z2wZ0f0PGQOcrMCIR_KNbGZ3U9nKV2cjI8OjTkVYXFgYcN3Irju92DOLLcWVvCkViV0KqAtabUdHvXorzHllvEagyhtXz8OhkhXAHD9vA63EkTt_bl9T3ZdQrENXdPi8gVTWdcRJhNbiANZYQfGJS7b4enMovTvTTxAFX6pvPyi_zaBrzMqU1Hgrmazl8z-vxqDYVfKWTw_1N7L9bcEg92SWHCRl0EUl1B7FrtRnM3kZa3_Spg1oliPGn8E7yjperS0hdDJXJJL0EYRrBDasSyLZ1fNPCYhpUPoi4dKOZyse1XJnRiJuBX9VYOBdl_9pg-9Bl1aig41orQaDom-8dhC1YCx9l6j-x_6UUGI7FxykJkv-X5pEbKRlexhhkU9VZ9umGWYVI5JpCV4_zp3VNlcQ2nlau1qPe9ifkhxlL43js8Bkicb5qjWgG1ybUSwdOmcmMXvjZKf2kXjPqcyu932LoQsX3ekdjNecOsXEJy8z4YMb3PNVrAltuNt4S2PKO8ivxQNUhSzHdlRutpiNi_CDlGSD0eFBe6CDhPBTTBPISteQlpBSBnFYQ.rWkmTS6c0WQqM6TbLDO9Qw","token_type":"bearer","expires_in":3600}%


kkamboj@OEC1092 Auth % curl -X POST "http://localhost:8000/register" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "karankamboj289",
    "email": "karankamboj289@gmail.com",
    "password": "TempPassword123!",
    "first_name": "Test",
    "last_name": "User"
  }'
{"message":"User registered successfully","user_sub":"448894e8-c0f1-70b1-9515-2b2ed78e602b","confirmation_required":true}%   



kkamboj@OEC1092 Auth % curl -X POST "http://localhost:8000/confirm-signup?username=karankamboj928&confirmation_code=332382" \
  -H "Content-Type: application/json"

{"message":"User confirmed successfully"}%   


curl -X POST "http://localhost:8000/auth/resend-confirmation" \
  -H "Content-Type: application/json" \
  -d '{
    "identifier": "karankamboj928"
  }'




aws cognito-idp create-user-pool-client \
  --user-pool-id "us-east-1_y82Pz5saV" \
  --client-name "MyAppClient-NoSecret" \
  --no-generate-secret \
  --explicit-auth-flows "ALLOW_USER_SRP_AUTH" "ALLOW_USER_PASSWORD_AUTH" "ALLOW_REFRESH_TOKEN_AUTH" \
  --token-validity-units '{
    "AccessToken": "hours",
    "IdToken": "hours",
    "RefreshToken": "days"
  }' \
  --access-token-validity 1 \
  --id-token-validity 1 \
  --refresh-token-validity 30 \
  --region us-east-1
