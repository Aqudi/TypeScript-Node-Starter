# Typescript Node Starter 소셜 로그인 구현 템플릿

## 소셜로그인 제공 업체
- facebook
- google
- kakao

## 사전준비물
1. 소셜로그인 제공 업체의 oAuth2 인증정보
2. SSL인증서 (openssl을 이용해서 발급)

## 사용법
1. .env.example 파일을 참고해서 .env파일에 인증정보와 인증서 파일 위치 작성
2. mongodb 컨테이너 실행
    ```shell
    docker run --name mongo -p 27017:27017 -d mongo
    ```