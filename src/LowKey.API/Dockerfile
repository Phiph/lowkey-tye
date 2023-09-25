FROM mcr.microsoft.com/dotnet/aspnet:7.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:7.0 AS build
WORKDIR /src
COPY ["LowKey.API/LowKey.API.csproj", "LowKey.API/"]
RUN dotnet restore "LowKey.API/LowKey.API.csproj"
COPY . .
WORKDIR "/src/LowKey.API"
RUN dotnet build "LowKey.API.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "LowKey.API.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "LowKey.API.dll"]
